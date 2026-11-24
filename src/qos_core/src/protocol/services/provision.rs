//! Quorum Key provisioning logic and types.
use qos_crypto::share_tree::{ShareTree, tree_shares_reconstruct};
use zeroize::Zeroizing;

use crate::protocol::{
	ProtocolError, ProtocolState,
	services::{
		app_key::{Settled, settle_quorum_key},
		boot::{Approval, ShareNode, VersionedManifestEnvelope},
	},
};

type Secret = Zeroizing<Vec<u8>>;
type Share = Zeroizing<Vec<u8>>;

/// Holds provisioned shares, one slot per share tree leaf, depth first.
pub(crate) struct SecretBuilder {
	shares: Vec<Option<Share>>,
}

impl SecretBuilder {
	/// Create a instance of [`Self`].
	pub fn new() -> Self {
		Self { shares: Vec::new() }
	}

	/// Whether `leaf` already holds a share.
	pub(crate) fn has_share(&self, leaf: usize) -> bool {
		self.shares.get(leaf).is_some_and(Option::is_some)
	}

	/// Hold `share` for `leaf` of `tree`.
	pub(crate) fn add_share(
		&mut self,
		tree: &ShareTree,
		leaf: usize,
		share: Share,
	) -> Result<(), ProtocolError> {
		if share.is_empty() {
			return Err(ProtocolError::InvalidShare);
		}
		if self.has_share(leaf) {
			return Err(ProtocolError::ShareAlreadyProvisioned);
		}
		self.shares.resize(tree.leaf_count(), None);
		let slot = self
			.shares
			.get_mut(leaf)
			.ok_or(ProtocolError::NotShareSetMember)?;
		*slot = Some(share);
		Ok(())
	}

	/// Reconstruct the secret once the held shares satisfy `tree`, or `None`
	/// before then.
	pub(crate) fn build(
		&self,
		tree: &ShareTree,
	) -> Result<Option<Secret>, ProtocolError> {
		let present: Vec<bool> =
			self.shares.iter().map(Option::is_some).collect();
		let satisfied = tree
			.is_satisfied(&present)
			.map_err(|e| ProtocolError::QosCrypto(format!("{e:?}")))?;
		if !satisfied {
			return Ok(None);
		}

		let secret = tree_shares_reconstruct(tree, &self.shares)
			.map_err(|e| ProtocolError::QosCrypto(format!("{e:?}")))?;
		if secret.is_empty() {
			return Err(ProtocolError::ReconstructionErrorEmptySecret);
		}

		Ok(Some(secret))
	}

	pub(crate) fn clear(&mut self) {
		self.shares = vec![];
	}
}

pub(in crate::protocol) fn provision(
	encrypted_share: &[u8],
	approval: Approval,
	state: &mut ProtocolState,
) -> Result<Option<Settled>, ProtocolError> {
	let manifest_envelope = state.handles.get_manifest_envelope()?;
	let manifest = manifest_envelope.manifest();
	let manifest_hash = manifest.manifest_hash();
	let share_set = manifest.share_set();
	share_set.validate()?;
	let tree = share_set.shape();

	// Check that the approval is valid
	// 1) the signature is valid. Note that we want to check signature before
	// interacting with data
	approval.verify(&manifest_hash)?;
	// 2) the approver belongs to the share set, and has not provisioned yet
	let leaf = share_set
		.leaf_index(&approval.member)
		.ok_or(ProtocolError::NotShareSetMember)?;
	if state.provisioner.has_share(leaf) {
		return Err(ProtocolError::ShareAlreadyProvisioned);
	}

	let ephemeral_key = state.handles.get_ephemeral_key()?;

	let share = ephemeral_key
		.decrypt(encrypted_share)
		.map_err(|_| ProtocolError::DecryptionFailed)?;
	if share.len() != qos_hybrid::MASTER_SEED_LEN + 1
		|| tree.leaf_identifier(leaf) != Some(share[0])
	{
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

	state.provisioner.add_share(&tree, leaf, share)?;

	// A finished or failed reconstruction drops the shares, so members can
	// provision again after a failure.
	let built = state.provisioner.build(&tree);
	if !matches!(built, Ok(None)) {
		state.provisioner.clear();
	}
	let Some(master_seed) = built? else {
		return Ok(None);
	};

	let master_seed: Zeroizing<[u8; qos_hybrid::MASTER_SEED_LEN]> =
		Zeroizing::new(
			master_seed[..]
				.try_into()
				.map_err(|_| ProtocolError::IncorrectSecretLen)?,
		);
	let pair = qos_hybrid::HybridPair::from_master_seed(&master_seed)?;
	let public_key_bytes = pair.public_key().to_bytes();

	if public_key_bytes != manifest.namespace().quorum_key {
		// We did not construct the intended key
		return Err(ProtocolError::ReconstructionErrorIncorrectPubKey);
	}

	// Write the keys and pivot, or wait for the app key when the manifest
	// names a minter: shares never carry one.
	settle_quorum_key(state, pair, None).map(Some)
}

#[cfg(test)]
mod test {
	use std::path::Path;

	use qos_crypto::{sha_256, shamir::shares_generate};
	use qos_hybrid::HybridPair;
	use qos_nsm::mock::MockNsm;
	use qos_test_primitives::PathWrapper;
	use zeroize::Zeroizing;

	use crate::{
		handles::Handles,
		protocol::{
			ProtocolError, ProtocolPhase, ProtocolState, QosHash,
			services::{
				app_key::Settled,
				boot::{
					Approval, Manifest, ManifestEnvelope, ManifestSet,
					Namespace, NitroConfig, PatchSet, PivotConfig,
					QuorumMember, RestartPolicy, ShareSet,
				},
				provision::provision,
			},
		},
	};

	struct Setup {
		quorum_pair: HybridPair,
		eph_pair: HybridPair,
		live_eph_pair: HybridPair,
		threshold: usize,
		state: ProtocolState,
		approvals: Vec<Approval>,
	}

	fn setup(
		eph_file: &Path,
		quorum_file: &Path,
		app_key_file: &Path,
		manifest_file: &Path,
	) -> Setup {
		let handles = Handles::new(
			eph_file.display().to_string(),
			quorum_file.display().to_string(),
			app_key_file.display().to_string(),
			manifest_file.display().to_string(),
			"pivot".to_string(),
		);
		// 1) Create and write eph key
		let eph_pair = HybridPair::generate().unwrap();
		let live_eph_pair = HybridPair::generate().unwrap();
		handles.put_ephemeral_key(&eph_pair).unwrap();
		// 2) Create and write manifest with threshold and quorum key
		let quorum_pair = HybridPair::generate().unwrap();
		let threshold = 3usize;
		let pivot = b"this is a pivot binary";

		let members: Vec<_> = (0..4)
			.map(|_| HybridPair::generate().unwrap())
			.enumerate()
			.map(|(i, pair)| {
				let member = QuorumMember {
					alias: i.to_string(),
					pub_key: pair.public_key().to_bytes(),
				};

				(member, pair)
			})
			.collect();

		let manifest = Manifest {
			namespace: Namespace {
				nonce: 420,
				name: "vape-space".to_string(),
				quorum_key: quorum_pair.public_key().to_bytes(),
			},
			enclave: NitroConfig {
				pcr0: vec![4; 32],
				pcr1: vec![3; 32],
				pcr2: vec![2; 32],
				pcr3: vec![1; 32],
				aws_root_certificate: b"cert lord".to_vec(),
				qos_commit: "mock qos commit".to_string(),
			},
			pivot: PivotConfig {
				hash: sha_256(pivot),
				restart: RestartPolicy::Always,
				args: vec![],
				..Default::default()
			},
			manifest_set: ManifestSet {
				threshold: threshold.try_into().unwrap(),
				members: vec![],
			},
			share_set: ShareSet {
				threshold: threshold.try_into().unwrap(),
				members: members.clone().into_iter().map(|(m, _)| m).collect(),
			},
			patch_set: PatchSet::default(),
		};

		let approvals: Vec<_> = members
			.into_iter()
			.map(|(member, pair)| {
				let approval = Approval {
					member,
					signature: pair.sign(&manifest.qos_hash()).unwrap(),
				};

				assert!(approval.verify(&manifest.qos_hash()).is_ok());

				approval
			})
			.collect();

		let manifest_envelope = ManifestEnvelope {
			manifest,
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		};
		handles.put_manifest_envelope(&manifest_envelope).unwrap();

		// 3) Create state with eph key and manifest
		let mut state =
			ProtocolState::new(Box::new(MockNsm::new()), handles, None);
		state.set_pending_live_ephemeral_key(live_eph_pair.clone());
		state.transition(ProtocolPhase::WaitingForQuorumShards).unwrap();

		Setup {
			quorum_pair,
			eph_pair,
			live_eph_pair,
			threshold,
			state,
			approvals,
		}
	}

	#[test]
	fn provision_works() {
		let quorum_file = PathWrapper::from("./provision_works.quorum.key");
		let app_key_file = PathWrapper::from("./provision_works.app.key");
		let eph_file = PathWrapper::from("./provision_works.eph.key");
		let manifest_file = PathWrapper::from("./provision_works.manifest");

		let Setup {
			quorum_pair,
			eph_pair,
			live_eph_pair,
			threshold,
			mut state,
			approvals,
		} = setup(&eph_file, &quorum_file, &app_key_file, &manifest_file);

		// 4) Create shards and encrypt them to eph key
		let quorum_key = quorum_pair.to_master_seed();
		let encrypted_shares: Vec<_> =
			shares_generate(&quorum_key[..], 4, threshold)
				.unwrap()
				.iter()
				.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
				.collect();

		// 5) For K-1 shards call provision, make sure returns false and doesn't
		// write quorum key
		for (i, share) in encrypted_shares[..threshold - 1].iter().enumerate() {
			let approval = approvals[i].clone();
			assert_eq!(provision(share, approval, &mut state), Ok(None));
			assert!(!Path::new(&*quorum_file).exists());
			assert_eq!(
				state.get_phase(),
				ProtocolPhase::WaitingForQuorumShards
			);
		}

		let boot_eph_key = std::fs::read(&*eph_file).unwrap();

		// 6) For shard K, call provision, make sure returns true and writes
		// quorum key as a ready only file
		let share = &encrypted_shares[threshold];
		let approval = approvals[threshold].clone();
		assert_eq!(
			provision(share, approval, &mut state),
			Ok(Some(Settled::Pivoting))
		);
		let quorum_key = std::fs::read(&*quorum_file).unwrap();

		assert_eq!(quorum_key, quorum_pair.to_master_seed_hex().as_slice());

		// A manifest naming no minter has no app key.
		assert!(state.handles.get_app_key().is_err());

		// Make sure the EK is persisted
		assert!(Path::new(&*eph_file).exists());

		// Make sure the EK rotation happened, post-boot
		let new_eph_key = std::fs::read(&*eph_file).unwrap();
		assert_ne!(new_eph_key, boot_eph_key);
		assert_eq!(new_eph_key, live_eph_pair.to_master_seed_hex().as_slice());

		// The share set approvals were recorded in the manifest envelope
		assert_eq!(
			state
				.handles
				.get_manifest_envelope()
				.unwrap()
				.share_set_approvals()
				.len(),
			threshold
		);
	}

	#[test]
	fn provision_rejects_the_wrong_key() {
		let eph_file =
			PathWrapper::from("./provision_rejects_the_wrong_key.eph.key");
		let quorum_file =
			PathWrapper::from("./provision_rejects_the_wrong_key.quorum.key");
		let app_key_file =
			PathWrapper::from("./provision_rejects_the_wrong_key.app.key");
		let manifest_file =
			PathWrapper::from("./provision_rejects_the_wrong_key.manifest");

		let Setup { eph_pair, threshold, mut state, approvals, .. } =
			setup(&eph_file, &quorum_file, &app_key_file, &manifest_file);

		// 4) Create shards of a RANDOM KEY and encrypt them to eph key
		let random_key = Zeroizing::new(
			HybridPair::generate().unwrap().to_master_seed().to_vec(),
		);
		let encrypted_shares: Vec<_> =
			shares_generate(&random_key, 4, threshold)
				.unwrap()
				.iter()
				.map(|shard| eph_pair.public_key().encrypt(&shard[..]).unwrap())
				.collect();

		// 5) For K-1 shards call provision, make sure returns false and doesn't
		// write quorum key
		for (i, share) in encrypted_shares[..threshold - 1].iter().enumerate() {
			let approval = approvals[i].clone();
			assert_eq!(provision(share, approval, &mut state), Ok(None));
			assert!(!Path::new(&*quorum_file).exists());
			assert_eq!(
				state.get_phase(),
				ProtocolPhase::WaitingForQuorumShards
			);
		}

		// 6) Add Kth shard of the random key
		let share = &encrypted_shares[threshold];
		let approval = approvals[threshold].clone();
		assert_eq!(
			provision(share, approval, &mut state),
			Err(ProtocolError::ReconstructionErrorIncorrectPubKey)
		);
		assert!(!Path::new(&*quorum_file).exists());
		// Note that the handler should set the state to unrecoverable error
		assert_eq!(state.get_phase(), ProtocolPhase::WaitingForQuorumShards);
	}

	#[test]
	fn provision_rejects_if_a_shard_is_invalid() {
		let eph_file = PathWrapper::from(
			"./provision_rejects_if_a_shard_is_invalid.eph.key",
		);
		let quorum_file = PathWrapper::from(
			"./provision_rejects_if_a_shard_is_invalid.quorum.key",
		);
		let app_key_file = PathWrapper::from(
			"./provision_rejects_if_a_shard_is_invalid.app.key",
		);
		let manifest_file = PathWrapper::from(
			"./provision_rejects_if_a_shard_is_invalid.manifest",
		);
		let Setup {
			quorum_pair,
			eph_pair,
			threshold,
			mut state,
			approvals,
			..
		} = setup(&eph_file, &quorum_file, &app_key_file, &manifest_file);

		// 4) Create shards and encrypt them to eph key
		let quorum_key = quorum_pair.to_master_seed();

		let encrypted_shares: Vec<_> =
			shares_generate(&quorum_key[..], 4, threshold)
				.unwrap()
				.iter()
				.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
				.collect();

		// 5) For K-1 shards call provision, make sure returns false and doesn't
		// write quorum key
		for (i, share) in encrypted_shares[..threshold - 1].iter().enumerate() {
			let approval = approvals[i].clone();
			assert_eq!(provision(share, approval, &mut state), Ok(None));
			assert!(!Path::new(&*quorum_file).exists());
			assert_eq!(
				state.get_phase(),
				ProtocolPhase::WaitingForQuorumShards
			);
		}

		// 6) A share whose identifier is not the member's position is refused
		// before it is held
		let misplaced_share =
			eph_pair.public_key().encrypt(&[69u8; 33]).unwrap();
		assert_eq!(
			provision(
				&misplaced_share,
				approvals[threshold].clone(),
				&mut state
			),
			Err(ProtocolError::ShareNotForMember)
		);

		// 7) Add a bogus shard at the member's position as the Kth shard
		let mut bogus_share = [69u8; 33];
		bogus_share[0] = u8::try_from(threshold + 1).unwrap();
		let encrypted_bogus_share =
			eph_pair.public_key().encrypt(&bogus_share).unwrap();
		let approval = approvals[threshold].clone();
		assert_eq!(
			provision(&encrypted_bogus_share, approval, &mut state),
			Err(ProtocolError::ReconstructionErrorIncorrectPubKey)
		);
		assert!(!Path::new(&*quorum_file).exists());
		// Note that the handler should set the state to unrecoverable error
		assert_eq!(state.get_phase(), ProtocolPhase::WaitingForQuorumShards);
	}

	#[test]
	fn provisions_rejects_if_an_approval_is_invalid() {
		let eph_file = PathWrapper::from(
			"./provisions_rejects_if_an_approval_is_invalid.eph.key",
		);
		let quorum_file = PathWrapper::from(
			"./provisions_rejects_if_an_approval_is_invalid.quorum.key",
		);
		let app_key_file = PathWrapper::from(
			"./provisions_rejects_if_an_approval_is_invalid.app.key",
		);
		let manifest_file = PathWrapper::from(
			"./provisions_rejects_if_an_approval_is_invalid.manifest",
		);

		let Setup {
			quorum_pair,
			eph_pair,
			threshold,
			mut state,
			mut approvals,
			..
		} = setup(&eph_file, &quorum_file, &app_key_file, &manifest_file);

		let quorum_key = quorum_pair.to_master_seed();
		let mut encrypted_shares: Vec<_> =
			shares_generate(&quorum_key[..], 4, threshold)
				.unwrap()
				.iter()
				.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
				.collect();

		let share = encrypted_shares.remove(0);
		let mut approval = approvals.remove(0);
		approval.signature =
			b"ffffffffffffffffffffffffffffffffffffffffffffff".to_vec();
		assert_eq!(
			provision(&share, approval, &mut state).unwrap_err(),
			ProtocolError::CouldNotVerifyApproval
		);
		assert!(!Path::new(&*quorum_file).exists());
		assert_eq!(state.get_phase(), ProtocolPhase::WaitingForQuorumShards);
	}

	#[test]
	fn provision_rejects_if_approval_is_not_from_share_set_member() {
		let eph_file = PathWrapper::from(
			"./provision_rejects_if_approval_is_not_from_share_set_member.eph.key",
		);
		let quorum_file = PathWrapper::from(
			"./provision_rejects_if_approval_is_not_from_share_set_member.quorum.key",
		);
		let app_key_file = PathWrapper::from(
			"./provision_rejects_if_approval_is_not_from_share_set_member.app.key",
		);
		let manifest_file = PathWrapper::from(
			"./provision_rejects_if_approval_is_not_from_share_set_member.manifest",
		);

		let Setup {
			quorum_pair,
			eph_pair,
			threshold,
			mut state,
			mut approvals,
			..
		} = setup(&eph_file, &quorum_file, &app_key_file, &manifest_file);

		let quorum_key = quorum_pair.to_master_seed();
		let mut encrypted_shares: Vec<_> =
			shares_generate(&quorum_key[..], 4, threshold)
				.unwrap()
				.iter()
				.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
				.collect();

		let manifest =
			state.handles.get_manifest_envelope().unwrap().manifest();
		let mut approval = approvals.remove(0);
		let pair = HybridPair::generate().unwrap();

		// Change the member so that are not recognized as part of the set
		approval.member.pub_key = pair.public_key().to_bytes();
		approval.signature = pair.sign(&manifest.qos_hash()).unwrap();

		let share = encrypted_shares.remove(0);
		assert_eq!(
			provision(&share, approval, &mut state).unwrap_err(),
			ProtocolError::NotShareSetMember
		);
		assert!(!Path::new(&*quorum_file).exists());
		assert_eq!(state.get_phase(), ProtocolPhase::WaitingForQuorumShards);
	}

	#[test]
	fn provision_rejects_with_signature_error_if_approval_is_not_from_share_set_member_and_bad_signature()
	 {
		let eph_file = PathWrapper::from(
			"./provision_rejects_with_signature_error_if_approval_is_not_from_share_set_member_and_bad_signature.eph.key",
		);
		let quorum_file = PathWrapper::from(
			"./provision_rejects_with_signature_error_if_approval_is_not_from_share_set_member_and_bad_signature.quorum.key",
		);
		let app_key_file = PathWrapper::from(
			"./provision_rejects_with_signature_error_if_approval_is_not_from_share_set_member_and_bad_signature.app.key",
		);
		let manifest_file = PathWrapper::from(
			"./provision_rejects_with_signature_error_if_approval_is_not_from_share_set_member_and_bad_signature.manifest",
		);

		let Setup {
			quorum_pair,
			eph_pair,
			threshold,
			mut state,
			mut approvals,
			..
		} = setup(&eph_file, &quorum_file, &app_key_file, &manifest_file);

		let quorum_key = quorum_pair.to_master_seed();
		let mut encrypted_shares: Vec<_> =
			shares_generate(&quorum_key[..], 4, threshold)
				.unwrap()
				.iter()
				.map(|shard| eph_pair.public_key().encrypt(shard).unwrap())
				.collect();

		let mut approval = approvals.remove(0);
		let pair = HybridPair::generate().unwrap();

		// Change the member so that are not recognized as part of the set
		approval.member.pub_key = pair.public_key().to_bytes();
		// DO NOT update the approval signature, so it doesn't match the pub key

		let share = encrypted_shares.remove(0);
		// we get an invalid signature error (not an error that they are not
		// part of the set)
		assert_eq!(
			provision(&share, approval, &mut state).unwrap_err(),
			ProtocolError::CouldNotVerifyApproval
		);
		assert!(!Path::new(&*quorum_file).exists());
		assert_eq!(state.get_phase(), ProtocolPhase::WaitingForQuorumShards);
	}

	mod share_tree {
		use qos_crypto::share_tree::tree_shares_generate;

		use super::*;
		use crate::protocol::services::boot::{
			ManifestBuilder, ShareGroup, ShareNode, VersionedManifestEnvelope,
			manifest::v2::ManifestEnvelopeV2,
		};

		struct TreeSetup {
			state: ProtocolState,
			quorum_pair: HybridPair,
			eph_pair: HybridPair,
			/// Every leaf, depth first: the five Umbra members, then the three
			/// external ones.
			leaves: Vec<(QuorumMember, HybridPair)>,
			approvals: Vec<Approval>,
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

		/// A v2 manifest whose share set is `root_threshold` of two groups:
		/// Umbra, 3 of 5, and external, 2 of 3.
		fn tree_setup(name: &str, root_threshold: u32) -> TreeSetup {
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

			let umbra: Vec<_> =
				(0..5).map(|i| member(&format!("umbra-{i}"))).collect();
			let external: Vec<_> =
				(0..3).map(|i| member(&format!("external-{i}"))).collect();
			let group =
				|alias: &str,
				 threshold,
				 members: &[(QuorumMember, HybridPair)]| ShareGroup {
					alias: alias.to_string(),
					threshold,
					members: members.iter().map(|(m, _)| m.clone()).collect(),
					groups: vec![],
				};
			let groups = vec![
				group("umbra", 3, &umbra),
				group("external", 2, &external),
			];

			let manifest = ManifestBuilder::v2()
				.namespace(Namespace {
					nonce: 1,
					name: "share-tree".to_string(),
					quorum_key: quorum_pair.public_key().to_bytes(),
				})
				.pivot_hash(sha_256(b"pivot"))
				.manifest_set(ManifestSet { threshold: 1, members: vec![] })
				.share_set(ShareSet {
					threshold: root_threshold,
					members: vec![],
				})
				.share_groups(groups)
				.enclave(NitroConfig::default())
				.build()
				.unwrap();
			let crate::protocol::services::boot::VersionedManifest::V2(
				manifest,
			) = manifest
			else {
				panic!("the builder makes v2 manifests by default");
			};

			let leaves: Vec<_> = umbra.into_iter().chain(external).collect();
			assert_eq!(
				manifest.share_set.leaves(),
				leaves.iter().map(|(m, _)| m).collect::<Vec<_>>(),
				"leaves run depth first: Umbra's members, then external's"
			);

			let envelope = VersionedManifestEnvelope::V2(ManifestEnvelopeV2 {
				manifest,
				manifest_set_approvals: vec![],
				share_set_approvals: vec![],
			});
			let hash = envelope.manifest_hash();
			let approvals = leaves
				.iter()
				.map(|(member, pair)| Approval {
					member: member.clone(),
					signature: pair.sign(&hash).unwrap(),
				})
				.collect();
			handles.put_manifest_envelope(envelope).unwrap();

			let mut state =
				ProtocolState::new(Box::new(MockNsm::new()), handles, None);
			state.set_pending_live_ephemeral_key(
				HybridPair::generate().unwrap(),
			);
			state.transition(ProtocolPhase::WaitingForQuorumShards).unwrap();

			TreeSetup {
				state,
				quorum_pair,
				eph_pair,
				leaves,
				approvals,
				quorum_file,
				_files: files,
			}
		}

		/// Each leaf's share as genesis would split it, encrypted to the
		/// setup ephemeral key.
		fn encrypted_shares(setup: &TreeSetup) -> Vec<Vec<u8>> {
			let manifest = setup.state.handles.get_manifest_envelope().unwrap();
			let tree = manifest.share_set().shape();
			tree_shares_generate(&setup.quorum_pair.to_master_seed()[..], &tree)
				.unwrap()
				.iter()
				.map(|share| {
					setup.eph_pair.public_key().encrypt(share).unwrap()
				})
				.collect()
		}

		/// Provision `leaves` in order, demanding all but the last leave the
		/// enclave waiting and the last one settle it.
		fn provision_until_settled(setup: &mut TreeSetup, leaves: &[usize]) {
			let shares = encrypted_shares(setup);
			let (last, waiting) = leaves.split_last().unwrap();
			for leaf in waiting {
				assert_eq!(
					provision(
						&shares[*leaf],
						setup.approvals[*leaf].clone(),
						&mut setup.state
					),
					Ok(None),
					"leaf {leaf} alone must not satisfy the share tree"
				);
			}
			assert_eq!(
				provision(
					&shares[*last],
					setup.approvals[*last].clone(),
					&mut setup.state
				),
				Ok(Some(Settled::Pivoting))
			);
		}

		#[test]
		fn both_groups_required_waits_for_the_second_group() {
			let name = "provision_tree_both_groups";
			let mut setup = tree_setup(name, 2);
			// Three Umbra members satisfy Umbra; the root still needs
			// external, so neither external share before the second settles.
			provision_until_settled(&mut setup, &[0, 5, 2, 4, 7]);
			assert_eq!(
				std::fs::read(&*setup.quorum_file).unwrap(),
				setup.quorum_pair.to_master_seed_hex().as_slice()
			);
			assert_eq!(
				setup
					.state
					.handles
					.get_manifest_envelope()
					.unwrap()
					.share_set_approvals()
					.len(),
				5
			);
		}

		#[test]
		fn either_group_alone_settles() {
			for (suffix, leaves) in
				[("umbra", vec![1, 3, 4]), ("external", vec![5, 7])]
			{
				let name = format!("provision_tree_either_group_{suffix}");
				let mut setup = tree_setup(&name, 1);
				provision_until_settled(&mut setup, &leaves);
				assert_eq!(
					std::fs::read(&*setup.quorum_file).unwrap(),
					setup.quorum_pair.to_master_seed_hex().as_slice()
				);
			}
		}

		#[test]
		fn a_member_cannot_provision_twice() {
			let name = "provision_tree_twice";
			let mut setup = tree_setup(name, 2);
			let shares = encrypted_shares(&setup);
			assert_eq!(
				provision(
					&shares[0],
					setup.approvals[0].clone(),
					&mut setup.state
				),
				Ok(None)
			);
			assert_eq!(
				provision(
					&shares[0],
					setup.approvals[0].clone(),
					&mut setup.state
				),
				Err(ProtocolError::ShareAlreadyProvisioned)
			);
			assert_eq!(
				setup
					.state
					.handles
					.get_manifest_envelope()
					.unwrap()
					.share_set_approvals()
					.len(),
				1,
				"a refused share must not record a second approval"
			);
		}

		#[test]
		fn a_share_for_another_leaf_is_refused() {
			let name = "provision_tree_wrong_leaf";
			let mut setup = tree_setup(name, 2);
			let shares = encrypted_shares(&setup);
			// Leaf 0's share carries identifier 1; leaf 1 expects 2.
			assert_eq!(
				provision(
					&shares[0],
					setup.approvals[1].clone(),
					&mut setup.state
				),
				Err(ProtocolError::ShareNotForMember)
			);
		}

		#[test]
		fn a_stranger_is_refused() {
			let name = "provision_tree_stranger";
			let mut setup = tree_setup(name, 2);
			let shares = encrypted_shares(&setup);
			let (stranger, pair) = member("stranger");
			let hash = setup
				.state
				.handles
				.get_manifest_envelope()
				.unwrap()
				.manifest_hash();
			let approval = Approval {
				member: stranger,
				signature: pair.sign(&hash).unwrap(),
			};
			assert_eq!(
				provision(&shares[0], approval, &mut setup.state),
				Err(ProtocolError::NotShareSetMember)
			);
			assert_eq!(setup.leaves.len(), 8);
		}
	}
}
