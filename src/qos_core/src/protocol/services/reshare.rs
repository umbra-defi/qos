//! Reshare: a provisioned enclave seals its quorum key under a fresh envelope key dealt over a new
//! holder tree, so holders change while the quorum key does not.
//!
//! The request names the new tree with its members' full keys and carries approvals of
//! [`reshare_digest`]: the current manifest's hash and the new tree as a manifest would name it.
//! The approvals must satisfy both the current holder tree, each approver placed by its key's
//! digests, and the manifest set's threshold, so the people who can recover the key now and the
//! people who approve manifests both consent to who can recover it next. The answer is the new
//! envelope and each new holder's encrypted shard, attested with the output's hash as user data.
//!
//! A holder removed by a reshare keeps its old shard and the old envelope; it loses the key only
//! once too few old shards survive to satisfy the old tree.

use std::{collections::BTreeSet, fmt};

use qos_crypto::sha_512;
use qos_nsm::types::{NsmRequest, NsmResponse};
use serde::{Deserialize, Serialize};

use crate::protocol::{
	ProtocolError, ProtocolState, QosHash,
	services::{
		boot::{Approval, ShareHolderNode, ShareNode, ShareSetV2},
		genesis::{GenesisMemberOutput, GenesisSet, deal_quorum_key},
	},
};

/// The domain label that opens [`reshare_digest`]'s preimage.
pub const RESHARE_DOMAIN: &[u8] = b"qos_quorum_key_reshare_v1";

/// What a reshare's approvers sign: SHA-512 over [`RESHARE_DOMAIN`], the current manifest's hash
/// and the canonical JSON of the new holder tree as a manifest names it, without an envelope
/// digest.
///
/// # Errors
///
/// [`ProtocolError::InvalidShareTree`] when the tree does not serialize.
pub fn reshare_digest(
	manifest_hash: &[u8],
	new_holders: &ShareSetV2,
) -> Result<[u8; 64], ProtocolError> {
	let holders = qos_json::to_vec(new_holders)
		.map_err(|e| ProtocolError::InvalidShareTree(format!("{e:?}")))?;
	let mut preimage = RESHARE_DOMAIN.to_vec();
	preimage.extend_from_slice(manifest_hash);
	preimage.extend_from_slice(&holders);
	Ok(sha_512(&preimage))
}

/// A reshare's output: the new tree, the unchanged quorum public key, each new holder's encrypted
/// shard and the new envelope.
#[derive(
	PartialEq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	Serialize,
	Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct ReshareOutput {
	/// The new holder tree, with full keys, exactly as requested.
	pub set: GenesisSet,
	/// The quorum public key, the same as before the reshare.
	#[serde(with = "qos_hex::serde")]
	pub quorum_key: Vec<u8>,
	/// Each new holder's encrypted envelope key shard, depth first.
	pub member_outputs: Vec<GenesisMemberOutput>,
	/// The encoded new envelope, which every new holder keeps beside its shard.
	#[serde(with = "qos_hex::serde")]
	pub envelope: Vec<u8>,
}

impl fmt::Debug for ReshareOutput {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("ReshareOutput")
			.field("set", &self.set)
			.field("quorum_key", &qos_hex::encode(&self.quorum_key))
			.field("member_outputs", &self.member_outputs)
			.finish_non_exhaustive()
	}
}

pub(in crate::protocol) fn reshare_quorum_key(
	state: &mut ProtocolState,
	new_set: &GenesisSet,
	approvals: &[Approval],
) -> Result<(ReshareOutput, NsmResponse), ProtocolError> {
	new_set.validate()?;
	let manifest_envelope = state.handles.get_manifest_envelope()?;
	let manifest = manifest_envelope.manifest();
	let current = manifest
		.share_set()
		.filter(|set| set.envelope_digest.is_some())
		.ok_or_else(|| {
			not_approved("the manifest holds no quorum key envelope to reshare")
		})?;

	// An approval that does not verify counts for nothing, so one bad upload cannot block the
	// rest.
	let digest =
		reshare_digest(&manifest.manifest_hash(), &new_set.holder_set()?)?;
	let approvals: Vec<&Approval> = approvals
		.iter()
		.filter(|approval| approval.verify(&digest).is_ok())
		.collect();

	let manifest_set = manifest.manifest_set()?;
	let manifest_approvers: BTreeSet<_> = approvals
		.iter()
		.filter_map(|approval| manifest_set.locate(&approval.member))
		.collect();
	if manifest_approvers.len() < manifest_set.threshold as usize {
		return Err(not_approved(
			"the approvals do not meet the manifest set's threshold",
		));
	}

	let holder_paths = approvals
		.iter()
		.filter_map(|approval| current.locate(&approval.member).ok().flatten())
		.collect();
	if !current.tree()?.is_satisfied_by(&holder_paths) {
		return Err(not_approved(
			"the approvals do not satisfy the current holder tree",
		));
	}

	let quorum_pair = state.handles.get_quorum_key()?;
	let quorum_key = quorum_pair.public_key().to_bytes();
	let (envelope, member_outputs) =
		deal_quorum_key(quorum_pair.to_master_seed(), &quorum_key, new_set)?;
	let output = ReshareOutput {
		set: new_set.clone(),
		quorum_key,
		member_outputs,
		envelope: envelope.encode(),
	};
	let nsm_response =
		state.attestor.nsm_process_request(NsmRequest::Attestation {
			user_data: Some(output.qos_hash().to_vec()),
			nonce: None,
			public_key: None,
		});
	Ok((output, nsm_response))
}

fn not_approved(reason: &str) -> ProtocolError {
	ProtocolError::ReshareNotApproved(reason.to_string())
}

#[cfg(test)]
mod test {
	use std::collections::BTreeMap;

	use qos_crypto::sha_256;
	use qos_hybrid::HybridPair;
	use qos_nsm::mock::MockNsm;
	use qos_test_primitives::PathWrapper;

	use super::*;
	use crate::{
		handles::Handles,
		protocol::services::{
			boot::{
				ManifestBuilder, ManifestSet, Namespace, NitroConfig,
				QuorumMember, ShareGroup, VersionedManifest,
				VersionedManifestEnvelope, manifest::v2::ManifestEnvelopeV2,
			},
			envelope::{
				QuorumKeyEnvelope, decode_shard, open_quorum_key,
				seal_quorum_key,
			},
		},
	};

	struct World {
		state: ProtocolState,
		quorum: HybridPair,
		/// u0, u1, u2 (Umbra, 2 of 3), e0, e1 (external, 1 of 2), then ext3 (new).
		people: Vec<(QuorumMember, HybridPair)>,
		manifest_hash: Vec<u8>,
		_files: [PathWrapper<String>; 4],
	}

	fn person(alias: &str) -> (QuorumMember, HybridPair) {
		let pair = HybridPair::generate().unwrap();
		(
			QuorumMember {
				alias: alias.to_string(),
				pub_key: pair.public_key().to_bytes(),
			},
			pair,
		)
	}

	fn tree_of(
		people: &[(QuorumMember, HybridPair)],
		umbra: &[usize],
		external: &[usize],
	) -> GenesisSet {
		let group = |alias: &str, threshold, indices: &[usize]| ShareGroup {
			alias: alias.to_string(),
			threshold,
			members: indices.iter().map(|i| people[*i].0.clone()).collect(),
			groups: vec![],
		};
		GenesisSet {
			threshold: 2,
			members: vec![],
			groups: vec![
				group("umbra", 2, umbra),
				group("external", 1, external),
			],
		}
	}

	/// A provisioned enclave whose manifest's tree is Umbra (u0-u2) and external (e0, e1), both
	/// needed, and whose manifest set is u0 and u1, both needed.
	fn world(name: &str) -> World {
		let files = ["eph", "quorum", "app", "manifest"]
			.map(|suffix| PathWrapper::from(format!("./{name}.{suffix}")));
		let handles = Handles::new(
			files[0].display().to_string(),
			files[1].display().to_string(),
			files[2].display().to_string(),
			files[3].display().to_string(),
			"pivot".to_string(),
		);
		let quorum = HybridPair::generate().unwrap();
		handles.put_quorum_key(&quorum).unwrap();
		let people: Vec<_> = ["u0", "u1", "u2", "e0", "e1", "ext3"]
			.iter()
			.map(|alias| person(alias))
			.collect();
		let mut holders =
			tree_of(&people, &[0, 1, 2], &[3, 4]).holder_set().unwrap();
		let (envelope, _) = seal_quorum_key(
			quorum.to_master_seed(),
			&quorum.public_key().to_bytes(),
			&holders.tree().unwrap(),
		)
		.unwrap();
		holders.envelope_digest = Some(envelope.digest().to_vec());
		let VersionedManifest::V2(manifest) = ManifestBuilder::v2()
			.namespace(Namespace {
				nonce: 1,
				name: "reshare".to_string(),
				quorum_key: quorum.public_key().to_bytes(),
			})
			.pivot_hash(sha_256(b"pivot"))
			.manifest_set(ManifestSet {
				threshold: 2,
				members: vec![people[0].0.clone(), people[1].0.clone()],
			})
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
		let manifest_hash = manifest_envelope.manifest_hash().to_vec();
		handles.put_manifest_envelope(manifest_envelope).unwrap();
		World {
			state: ProtocolState::new(Box::new(MockNsm::new()), handles, None),
			quorum,
			people,
			manifest_hash,
			_files: files,
		}
	}

	impl World {
		/// Drops e0, adds ext3.
		fn new_tree(&self) -> GenesisSet {
			tree_of(&self.people, &[0, 1, 2], &[4, 5])
		}

		fn approvals(
			&self,
			signers: &[usize],
			set: &GenesisSet,
		) -> Vec<Approval> {
			let digest =
				reshare_digest(&self.manifest_hash, &set.holder_set().unwrap())
					.unwrap();
			signers
				.iter()
				.map(|i| Approval {
					member: self.people[*i].0.clone(),
					signature: self.people[*i].1.sign(&digest).unwrap(),
				})
				.collect()
		}
	}

	#[test]
	fn the_new_holders_recover_the_same_quorum_key() {
		let mut world = world("reshare_works");
		let new_set = world.new_tree();
		let approvals = world.approvals(&[0, 1, 3], &new_set);
		let (output, _) =
			reshare_quorum_key(&mut world.state, &new_set, &approvals).unwrap();
		assert_eq!(output.quorum_key, world.quorum.public_key().to_bytes());

		let envelope = QuorumKeyEnvelope::decode(&output.envelope).unwrap();
		let holders = new_set.holder_set().unwrap();
		let mut shards = BTreeMap::new();
		for (member_output, index) in
			output.member_outputs.iter().zip([0, 1, 2, 4, 5])
		{
			assert_eq!(member_output.share_set_member, world.people[index].0);
			if [0, 2, 5].contains(&index) {
				let encoded = world.people[index]
					.1
					.decrypt(&member_output.encrypted_shard)
					.unwrap();
				let (_, shard) = decode_shard(&encoded).unwrap();
				let path =
					holders.locate(&world.people[index].0).unwrap().unwrap();
				shards.insert(path, shard);
			}
		}
		let seed = open_quorum_key(
			&envelope,
			&output.quorum_key,
			&holders.tree().unwrap(),
			&shards,
		)
		.unwrap();
		assert_eq!(seed[..], world.quorum.to_master_seed()[..]);
	}

	#[test]
	fn the_current_holder_tree_must_consent() {
		let mut world = world("reshare_tree_consent");
		let new_set = world.new_tree();
		let only_umbra = world.approvals(&[0, 1, 2], &new_set);
		assert!(matches!(
			reshare_quorum_key(&mut world.state, &new_set, &only_umbra),
			Err(ProtocolError::ReshareNotApproved(_))
		));
	}

	#[test]
	fn the_manifest_set_must_consent() {
		let mut world = world("reshare_manifest_consent");
		let new_set = world.new_tree();
		let no_u1 = world.approvals(&[0, 2, 4], &new_set);
		assert!(matches!(
			reshare_quorum_key(&mut world.state, &new_set, &no_u1),
			Err(ProtocolError::ReshareNotApproved(_))
		));
	}

	#[test]
	fn an_approval_that_does_not_verify_is_ignored() {
		let mut world = world("reshare_junk_approval");
		let new_set = world.new_tree();
		let mut approvals = world.approvals(&[0, 1, 3], &new_set);
		let mut junk = approvals[0].clone();
		junk.signature[0] ^= 1;
		approvals.insert(0, junk);
		let other = tree_of(&world.people, &[0, 1, 2], &[3, 5]);
		approvals.extend(world.approvals(&[4], &other));
		let (output, _) =
			reshare_quorum_key(&mut world.state, &new_set, &approvals).unwrap();
		assert_eq!(output.set, new_set);
	}

	#[test]
	fn approvals_of_another_tree_are_refused() {
		let mut world = world("reshare_other_tree");
		let new_set = world.new_tree();
		let other = tree_of(&world.people, &[0, 1, 2], &[3, 5]);
		let approvals = world.approvals(&[0, 1, 3], &other);
		assert!(matches!(
			reshare_quorum_key(&mut world.state, &new_set, &approvals),
			Err(ProtocolError::ReshareNotApproved(_))
		));
	}
}
