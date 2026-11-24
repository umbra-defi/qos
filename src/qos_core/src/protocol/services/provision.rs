//! Quorum Key provisioning: rebuild the envelope key from holders' shards and open the quorum key
//! envelope the manifest names.
//!
//! A booted enclave first takes the envelope ([`provide_quorum_key_envelope`]), accepted only when
//! its digest is the manifest's. Each holder then posts its shard re-encrypted to the setup
//! ephemeral key with an approval whose key's digests place it at one holder of the tree
//! ([`provision`]). Once the shards satisfy the tree, the enclave rebuilds the envelope key, opens
//! the master seed and checks it is the namespace's quorum key.

use std::collections::BTreeMap;

use qos_nested_shamir::{Path, Shard};
use zeroize::Zeroizing;

use crate::protocol::{
	ProtocolError, ProtocolState,
	services::{
		app_key::{Settled, settle_quorum_key},
		boot::{Approval, ShareHolderNode, VersionedManifestEnvelope},
		envelope::{QuorumKeyEnvelope, decode_shard, open_quorum_key},
	},
};

/// What a boot holds while it collects shards: the envelope, once provided, and each holder's
/// shard by path.
pub(crate) struct SecretBuilder {
	envelope: Option<QuorumKeyEnvelope>,
	shards: BTreeMap<Path, Shard>,
}

impl SecretBuilder {
	/// Create a instance of [`Self`].
	pub fn new() -> Self {
		Self { envelope: None, shards: BTreeMap::new() }
	}
}

/// Accept the quorum key envelope whose digest the manifest names.
///
/// # Errors
///
/// [`ProtocolError::QuorumKeyEnvelope`] for a manifest without a holder tree or envelope digest,
/// an envelope that does not decode, or one whose digest is not the manifest's.
pub(in crate::protocol) fn provide_quorum_key_envelope(
	encoded: &[u8],
	state: &mut ProtocolState,
) -> Result<(), ProtocolError> {
	let manifest_envelope = state.handles.get_manifest_envelope()?;
	let expected = manifest_envelope
		.share_set()
		.and_then(|set| set.envelope_digest.clone())
		.ok_or_else(|| {
			ProtocolError::QuorumKeyEnvelope(
				"the manifest names no quorum key envelope".to_string(),
			)
		})?;
	let envelope = QuorumKeyEnvelope::decode(encoded)?;
	if envelope.digest()[..] != expected[..] {
		return Err(ProtocolError::QuorumKeyEnvelope(
			"the envelope is not the one the manifest names".to_string(),
		));
	}
	state.provisioner.envelope = Some(envelope);
	Ok(())
}

pub(in crate::protocol) fn provision(
	encrypted_share: &[u8],
	approval: Approval,
	state: &mut ProtocolState,
) -> Result<Option<Settled>, ProtocolError> {
	let manifest_envelope = state.handles.get_manifest_envelope()?;
	let manifest = manifest_envelope.manifest();
	let manifest_hash = manifest.manifest_hash();
	let share_set = manifest.share_set().ok_or_else(|| {
		ProtocolError::QuorumKeyEnvelope(
			"a v0 or v1 manifest has no holder tree to provision".to_string(),
		)
	})?;
	let tree = share_set.tree()?;
	let Some(envelope) = state.provisioner.envelope.clone() else {
		return Err(ProtocolError::QuorumKeyEnvelopeNotProvided);
	};

	// 1) the signature is valid, before touching anything the approver sent
	approval.verify(&manifest_hash)?;
	// 2) the approver's key is a holder of the tree that has not posted yet
	let path = share_set
		.locate(&approval.member)?
		.ok_or(ProtocolError::NotShareSetMember)?;
	if state.provisioner.shards.contains_key(&path) {
		return Err(ProtocolError::ShareAlreadyProvisioned);
	}

	let ephemeral_key = state.handles.get_ephemeral_key()?;
	let decrypted = Zeroizing::new(
		ephemeral_key
			.decrypt(encrypted_share)
			.map_err(|_| ProtocolError::DecryptionFailed)?,
	);
	let (deal_id, shard) = decode_shard(&decrypted)?;
	if deal_id != envelope.deal_id {
		return Err(ProtocolError::ShareNotForMember);
	}

	// Record the share set approval
	state.handles.mutate_manifest_envelope(|mut envelope| {
		match &mut envelope {
			VersionedManifestEnvelope::V2(inner) => {
				inner.share_set_approvals.push(approval);
			}
			VersionedManifestEnvelope::V1(inner) => {
				inner.share_set_approvals.push(approval);
			}
			VersionedManifestEnvelope::V0(inner) => {
				inner.share_set_approvals.push(approval);
			}
		}
		envelope
	})?;
	state.provisioner.shards.insert(path, shard);

	let present = state.provisioner.shards.keys().copied().collect();
	if !tree.is_satisfied_by(&present) {
		return Ok(None);
	}

	// A finished or failed reconstruction drops the shards, so holders can post again after a
	// failure.
	let quorum_key = manifest.namespace().quorum_key.clone();
	let opened = open_quorum_key(
		&envelope,
		&quorum_key,
		&tree,
		&state.provisioner.shards,
	);
	state.provisioner.shards.clear();
	let master_seed = opened?;

	let pair = qos_hybrid::HybridPair::from_master_seed(&master_seed)?;
	if pair.public_key().to_bytes() != quorum_key {
		return Err(ProtocolError::ReconstructionErrorIncorrectPubKey);
	}

	// Write the keys and pivot, or wait for the app key when the manifest
	// names a minter: shares never carry one.
	settle_quorum_key(state, pair, None).map(Some)
}

#[cfg(test)]
mod test {
	use qos_crypto::sha_256;
	use qos_hybrid::HybridPair;
	use qos_nsm::mock::MockNsm;
	use qos_test_primitives::PathWrapper;

	use super::*;
	use crate::{
		handles::Handles,
		protocol::{
			ProtocolPhase,
			services::{
				boot::{
					ManifestBuilder, ManifestSet, Namespace, NitroConfig,
					QuorumMember, ShareGroup, ShareNode, VersionedManifest,
					manifest::v2::ManifestEnvelopeV2,
				},
				envelope::{encode_shard, seal_quorum_key},
				genesis::GenesisSet,
			},
		},
	};

	struct Setup {
		state: ProtocolState,
		quorum_pair: HybridPair,
		eph_pair: HybridPair,
		/// Umbra's three members, then external's two.
		members: Vec<(QuorumMember, HybridPair)>,
		approvals: Vec<Approval>,
		envelope: QuorumKeyEnvelope,
		shards: Vec<Shard>,
		quorum_file: PathWrapper<String>,
		_files: [PathWrapper<String>; 3],
	}

	fn member(alias: &str) -> (QuorumMember, HybridPair) {
		let pair = HybridPair::generate().unwrap();
		let member = QuorumMember {
			alias: alias.to_string(),
			pub_key: pair.public_key().to_bytes(),
		};
		(member, pair)
	}

	/// A manifest whose holder tree needs `root_threshold` of Umbra (2 of 3) and external
	/// (1 of 2), with the quorum key sealed in an envelope dealt over it.
	fn setup(name: &str, root_threshold: u32) -> Setup {
		let quorum_file = PathWrapper::from(format!("./{name}.quorum.key"));
		let files = [
			PathWrapper::from(format!("./{name}.eph.key")),
			PathWrapper::from(format!("./{name}.app.key")),
			PathWrapper::from(format!("./{name}.manifest")),
		];
		let handles = Handles::new(
			files[0].display().to_string(),
			quorum_file.display().to_string(),
			files[1].display().to_string(),
			files[2].display().to_string(),
			"pivot".to_string(),
		);
		let eph_pair = HybridPair::generate().unwrap();
		handles.put_ephemeral_key(&eph_pair).unwrap();
		let quorum_pair = HybridPair::generate().unwrap();
		let quorum_public = quorum_pair.public_key().to_bytes();

		let members: Vec<_> = ["u0", "u1", "u2", "e0", "e1"]
			.iter()
			.map(|alias| member(alias))
			.collect();
		let group = |alias: &str, threshold, range: std::ops::Range<usize>| {
			ShareGroup {
				alias: alias.to_string(),
				threshold,
				members: members[range]
					.iter()
					.map(|(m, _)| m.clone())
					.collect(),
				groups: vec![],
			}
		};
		let genesis = GenesisSet {
			threshold: root_threshold,
			members: vec![],
			groups: vec![group("umbra", 2, 0..3), group("external", 1, 3..5)],
		};
		let mut holders = genesis.holder_set().unwrap();
		let tree = holders.tree().unwrap();
		let (envelope, by_path) = seal_quorum_key(
			quorum_pair.to_master_seed(),
			&quorum_public,
			&tree,
		)
		.unwrap();
		holders.envelope_digest = Some(envelope.digest().to_vec());
		let shards = members
			.iter()
			.map(|(m, _)| by_path[&holders.locate(m).unwrap().unwrap()].clone())
			.collect();

		let VersionedManifest::V2(manifest) = ManifestBuilder::v2()
			.namespace(Namespace {
				nonce: 1,
				name: "envelope".to_string(),
				quorum_key: quorum_public,
			})
			.pivot_hash(sha_256(b"pivot"))
			.manifest_set(ManifestSet { threshold: 1, members: vec![] })
			.share_holders(holders)
			.enclave(NitroConfig::default())
			.build()
			.unwrap()
		else {
			panic!("the builder makes v2 manifests by default");
		};
		let manifest_envelope =
			VersionedManifestEnvelope::V2(ManifestEnvelopeV2 {
				manifest,
				manifest_set_approvals: vec![],
				share_set_approvals: vec![],
			});
		let hash = manifest_envelope.manifest_hash();
		let approvals = members
			.iter()
			.map(|(member, pair)| Approval {
				member: member.clone(),
				signature: pair.sign(&hash).unwrap(),
			})
			.collect();
		handles.put_manifest_envelope(manifest_envelope).unwrap();

		let mut state =
			ProtocolState::new(Box::new(MockNsm::new()), handles, None);
		state.set_pending_live_ephemeral_key(HybridPair::generate().unwrap());
		state.transition(ProtocolPhase::WaitingForQuorumShards).unwrap();

		Setup {
			state,
			quorum_pair,
			eph_pair,
			members,
			approvals,
			envelope,
			shards,
			quorum_file,
			_files: files,
		}
	}

	impl Setup {
		fn provide_envelope(&mut self) {
			provide_quorum_key_envelope(
				&self.envelope.encode(),
				&mut self.state,
			)
			.unwrap();
		}

		fn seal(
			&self,
			deal_id: &qos_nested_shamir::DealId,
			index: usize,
		) -> Vec<u8> {
			let encoded = encode_shard(deal_id, &self.shards[index]);
			self.eph_pair.public_key().encrypt(&encoded).unwrap()
		}

		fn post(
			&mut self,
			index: usize,
		) -> Result<Option<Settled>, ProtocolError> {
			let sealed = self.seal(&self.envelope.deal_id, index);
			provision(&sealed, self.approvals[index].clone(), &mut self.state)
		}
	}

	#[test]
	fn either_group_alone_opens_the_quorum_key() {
		for (suffix, holders) in [("umbra", vec![0, 2]), ("external", vec![4])]
		{
			let mut setup = setup(&format!("provision_either_{suffix}"), 1);
			setup.provide_envelope();
			let (last, waiting) = holders.split_last().unwrap();
			for holder in waiting {
				assert_eq!(setup.post(*holder), Ok(None));
			}
			assert_eq!(setup.post(*last), Ok(Some(Settled::Pivoting)));
			assert_eq!(
				std::fs::read(&*setup.quorum_file).unwrap(),
				setup.quorum_pair.to_master_seed_hex().as_slice()
			);
		}
	}

	#[test]
	fn both_groups_required_waits_for_the_second() {
		let mut setup = setup("provision_both_groups", 2);
		setup.provide_envelope();
		for holder in [0, 1] {
			assert_eq!(setup.post(holder), Ok(None));
		}
		assert_eq!(setup.post(3), Ok(Some(Settled::Pivoting)));
		let approvals = setup
			.state
			.handles
			.get_manifest_envelope()
			.unwrap()
			.share_set_approvals()
			.len();
		assert_eq!(approvals, 3);
	}

	#[test]
	fn a_shard_before_the_envelope_is_refused() {
		let mut setup = setup("provision_no_envelope", 1);
		assert_eq!(
			setup.post(0),
			Err(ProtocolError::QuorumKeyEnvelopeNotProvided)
		);
	}

	#[test]
	fn only_the_named_envelope_is_accepted() {
		let mut setup = setup("provision_wrong_envelope", 1);
		let tree = setup
			.state
			.handles
			.get_manifest_envelope()
			.unwrap()
			.share_set()
			.unwrap()
			.tree()
			.unwrap();
		let (other, _) = seal_quorum_key(
			setup.quorum_pair.to_master_seed(),
			&setup.quorum_pair.public_key().to_bytes(),
			&tree,
		)
		.unwrap();
		assert!(matches!(
			provide_quorum_key_envelope(&other.encode(), &mut setup.state),
			Err(ProtocolError::QuorumKeyEnvelope(_))
		));
	}

	#[test]
	fn a_holder_cannot_post_twice_and_a_stranger_cannot_post() {
		let mut setup = setup("provision_twice", 2);
		setup.provide_envelope();
		assert_eq!(setup.post(0), Ok(None));
		assert_eq!(setup.post(0), Err(ProtocolError::ShareAlreadyProvisioned));

		let (stranger, pair) = member("stranger");
		let hash = setup
			.state
			.handles
			.get_manifest_envelope()
			.unwrap()
			.manifest_hash();
		let approval =
			Approval { member: stranger, signature: pair.sign(&hash).unwrap() };
		let sealed = setup.seal(&setup.envelope.deal_id, 1);
		assert_eq!(
			provision(&sealed, approval, &mut setup.state),
			Err(ProtocolError::NotShareSetMember)
		);
		assert_eq!(setup.members.len(), 5);
	}

	#[test]
	fn a_shard_of_another_deal_is_refused() {
		let mut setup = setup("provision_other_deal", 1);
		setup.provide_envelope();
		let mut other_deal = setup.envelope.deal_id;
		other_deal.0[0] ^= 1;
		let sealed = setup.seal(&other_deal, 0);
		assert_eq!(
			provision(&sealed, setup.approvals[0].clone(), &mut setup.state),
			Err(ProtocolError::ShareNotForMember)
		);
	}
}
