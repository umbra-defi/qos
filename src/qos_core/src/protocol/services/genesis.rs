//! Genesis boot logic and types.

use std::fmt;

use qos_crypto::sha_512;
use qos_hybrid::{HybridPair, HybridPublic};
use qos_nsm::types::{NsmRequest, NsmResponse};
use serde::{Deserialize, Serialize};

use crate::protocol::{
	ProtocolError, ProtocolState, QosHash,
	services::{
		boot::{QuorumMember, ShareGroup, ShareHolderNode, ShareNode},
		envelope::{QuorumKeyEnvelope, encode_shard, seal_quorum_key},
	},
};

const QOS_TEST_MESSAGE: &[u8] = b"qos-test-message";

/// Configuration for sharding a Quorum Key created in the Genesis flow.
#[derive(
	PartialEq,
	Debug,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
pub struct GenesisSet {
	/// Share Set Member's who's production key will be used to encrypt Genesis
	/// flow outputs.
	pub members: Vec<QuorumMember>,
	/// Threshold for successful reconstitution of the Quorum Key shards
	#[serde(with = "qos_json::string_or_numeric")]
	pub threshold: u32,
	/// Groups that each recover one share of the Quorum Key, after
	/// [`Self::members`]; the threshold counts them alongside the members.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub groups: Vec<ShareGroup>,
}

impl ShareNode for GenesisSet {
	fn threshold(&self) -> u32 {
		self.threshold
	}
	fn members(&self) -> &[QuorumMember] {
		&self.members
	}
	fn groups(&self) -> &[ShareGroup] {
		&self.groups
	}
}

#[derive(
	PartialEq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	Serialize,
	Deserialize,
)]
struct MemberShard {
	/// Member of the Setup Set.
	member: QuorumMember,
	/// Shard of the generated Quorum Key, encrypted to the `member`s Setup
	/// Key.
	#[serde(with = "qos_hex::serde")]
	shard: Vec<u8>,
}

impl fmt::Debug for MemberShard {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MemberShard")
			.field("member", &self.member)
			.field("shard", &qos_hex::encode(&self.shard))
			.finish()
	}
}

/// A set of member shards used to successfully recover the quorum key during
/// the genesis ceremony.
#[derive(
	PartialEq,
	Debug,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	Serialize,
	Deserialize,
)]
pub struct RecoveredPermutation(Vec<MemberShard>);

/// Genesis output per Setup Member.
#[derive(
	PartialEq,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct GenesisMemberOutput {
	/// The holder this shard was dealt to.
	pub share_set_member: QuorumMember,
	/// The holder's envelope key shard, [`encode_shard`]'s deal id and 64 bytes, encrypted to the
	/// holder's key.
	#[serde(with = "qos_hex::serde")]
	pub encrypted_shard: Vec<u8>,
	/// SHA-512 of the plaintext encoded shard, for the holder to check its decryption.
	#[serde(with = "qos_hex::serde")]
	pub shard_hash: [u8; 64],
}

impl fmt::Debug for GenesisMemberOutput {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("GenesisMemberOutput")
			.field("share_set_member", &self.share_set_member)
			.field("encrypted_shard", &qos_hex::encode(&self.encrypted_shard))
			.field("shard_hash", &qos_hex::encode(&self.shard_hash))
			.finish()
	}
}

/// Output from running Genesis Boot. Should contain all information relevant to
/// how the quorum shares where created.
#[derive(
	PartialEq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	Serialize,
	Deserialize,
)]
pub struct GenesisOutput {
	/// The exact [`GenesisSet`] from the boot genesis request this output was
	/// generated for. Intentionally has no serde/borsh default so
	/// pre-request-echo peers and outputs fail closed on decode.
	pub set: GenesisSet,
	/// The exact DR key from the boot genesis request, if one was provided.
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		with = "qos_hex::serde::option"
	)]
	pub dr_key: Option<Vec<u8>>,
	/// Public Quorum Key, DER encoded.
	#[serde(with = "qos_hex::serde")]
	pub quorum_key: Vec<u8>,
	/// Each holder's encrypted envelope key shard, depth first.
	pub member_outputs: Vec<GenesisMemberOutput>,
	/// The encoded [`QuorumKeyEnvelope`] the master seed is sealed in, which every holder keeps
	/// beside its shard and every manifest names by digest.
	#[serde(with = "qos_hex::serde")]
	pub envelope: Vec<u8>,
	/// All successfully `RecoveredPermutation`s completed during the genesis
	/// process.
	pub recovery_permutations: Vec<RecoveredPermutation>,
	/// The quorum key encrypted to the DR key. None if no DR Key was provided
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		with = "qos_hex::serde::option"
	)]
	pub dr_key_wrapped_quorum_key: Option<Vec<u8>>,
	/// Hash of the quorum key secret
	#[serde(with = "qos_hex::serde")]
	pub quorum_key_hash: [u8; 64],
	/// Test message encrypted to the quorum public key.
	#[serde(with = "qos_hex::serde")]
	pub test_message_ciphertext: Vec<u8>,
	/// Signature over the test message by the quorum key.
	#[serde(with = "qos_hex::serde")]
	pub test_message_signature: Vec<u8>,
	/// The message that was used to generate [`Self::test_message_signature`]
	/// and [`Self::test_message_ciphertext`]
	#[serde(with = "qos_hex::serde")]
	pub test_message: Vec<u8>,
}

impl fmt::Debug for GenesisOutput {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("GenesisOutput")
			.field("set", &self.set)
			.field("quorum_key", &qos_hex::encode(&self.quorum_key))
			.field("member_outputs", &self.member_outputs)
			.field("recovery_permutations", &self.recovery_permutations)
			.finish_non_exhaustive()
	}
}

/// Seals `master_seed` under a fresh envelope key dealt over `holders`' tree, and encrypts each
/// holder's encoded shard to its key, depth first. Genesis and reshare both deal this way.
///
/// # Errors
///
/// As [`ShareNode::holder_set`], [`seal_quorum_key`] and the holders' encryption.
pub(in crate::protocol) fn deal_quorum_key<N: ShareNode>(
	master_seed: &[u8; qos_hybrid::MASTER_SEED_LEN],
	quorum_public_key: &[u8],
	holders: &N,
) -> Result<(QuorumKeyEnvelope, Vec<GenesisMemberOutput>), ProtocolError> {
	let holder_set = holders.holder_set()?;
	let tree = holder_set.tree()?;
	let (envelope, shards) =
		seal_quorum_key(master_seed, quorum_public_key, &tree)?;
	let member_outputs = holders
		.leaves()
		.into_iter()
		.map(|member| {
			let path = holder_set.locate(member)?.ok_or(
				ProtocolError::InvalidShareTree(
					"a member has no holder in its own tree".to_string(),
				),
			)?;
			let encoded = encode_shard(&envelope.deal_id, &shards[&path]);
			Ok(GenesisMemberOutput {
				share_set_member: member.clone(),
				encrypted_shard: HybridPublic::from_bytes(&member.pub_key)?
					.encrypt(&encoded)?,
				shard_hash: sha_512(&encoded),
			})
		})
		.collect::<Result<_, ProtocolError>>()?;
	Ok((envelope, member_outputs))
}

pub(in crate::protocol) fn boot_genesis(
	state: &mut ProtocolState,
	genesis_set: &GenesisSet,
	maybe_dr_key: Option<Vec<u8>>,
) -> Result<(GenesisOutput, NsmResponse), ProtocolError> {
	genesis_set.validate()?;

	let quorum_pair = HybridPair::generate()?;
	let seed = quorum_pair.to_master_seed();
	let master_seed = &seed[..];
	let quorum_public = quorum_pair.public_key().to_bytes();

	let (envelope, member_outputs) =
		deal_quorum_key(seed, &quorum_public, genesis_set)?;

	let dr_key_wrapped_quorum_key = if let Some(dr_key) = &maybe_dr_key {
		let dr_public = HybridPublic::from_bytes(dr_key)
			.map_err(ProtocolError::InvalidDRKey)?;
		Some(dr_public.encrypt(master_seed)?)
	} else {
		None
	};

	let hex_master_seed = zeroize::Zeroizing::new(qos_hex::encode(master_seed));
	let genesis_output = GenesisOutput {
		set: genesis_set.clone(),
		dr_key: maybe_dr_key,
		member_outputs,
		envelope: envelope.encode(),
		quorum_key: quorum_public,
		// TODO: generate N choose K recovery permutations
		recovery_permutations: vec![],
		dr_key_wrapped_quorum_key,
		quorum_key_hash: sha_512(hex_master_seed.as_bytes()),
		test_message_ciphertext: quorum_pair
			.public_key()
			.encrypt(QOS_TEST_MESSAGE)?,
		test_message_signature: quorum_pair.sign(QOS_TEST_MESSAGE)?,
		test_message: QOS_TEST_MESSAGE.to_vec(),
	};

	let nsm_response = {
		let request = NsmRequest::Attestation {
			user_data: Some(genesis_output.qos_hash().to_vec()),
			nonce: None,
			public_key: None,
		};
		state.attestor.nsm_process_request(request)
	};

	Ok((genesis_output, nsm_response))
}

#[cfg(test)]
mod test {
	use std::collections::BTreeMap;

	use qos_nsm::mock::MockNsm;

	use super::*;
	use crate::{
		handles::Handles,
		protocol::services::envelope::{decode_shard, open_quorum_key},
	};

	fn state(name: &str) -> ProtocolState {
		let handles = Handles::new(
			format!("EPH.{name}"),
			format!("QUO.{name}"),
			format!("QUO.{name}.app"),
			format!("MAN.{name}"),
			format!("PIV.{name}"),
		);
		ProtocolState::new(Box::new(MockNsm::new()), handles, None)
	}

	fn member(index: usize, pair: &HybridPair) -> QuorumMember {
		QuorumMember {
			alias: format!("member{index}"),
			pub_key: pair.public_key().to_bytes(),
		}
	}

	#[test]
	fn genesis_seals_the_quorum_key_in_an_envelope_dealt_over_the_tree() {
		let pairs: Vec<_> =
			(0..5).map(|_| HybridPair::generate().unwrap()).collect();
		let group =
			|alias: &str, threshold, members: Vec<QuorumMember>| ShareGroup {
				alias: alias.to_string(),
				threshold,
				members,
				groups: vec![],
			};
		let genesis_set = GenesisSet {
			members: vec![],
			threshold: 2,
			groups: vec![
				group(
					"umbra",
					2,
					vec![
						member(0, &pairs[0]),
						member(1, &pairs[1]),
						member(2, &pairs[2]),
					],
				),
				group(
					"external",
					1,
					vec![member(3, &pairs[3]), member(4, &pairs[4])],
				),
			],
		};

		let (output, _) =
			boot_genesis(&mut state("envelope"), &genesis_set, None).unwrap();
		assert_eq!(output.set, genesis_set);
		let envelope = QuorumKeyEnvelope::decode(&output.envelope).unwrap();
		let holders = genesis_set.holder_set().unwrap();
		let tree = holders.tree().unwrap();
		assert_eq!(envelope.tree_digest, tree.digest().0);

		let mut shards = BTreeMap::new();
		for (index, (output, pair)) in
			output.member_outputs.iter().zip(&pairs).enumerate()
		{
			assert_eq!(output.share_set_member, member(index, pair));
			let encoded = pair.decrypt(&output.encrypted_shard).unwrap();
			assert_eq!(sha_512(&encoded), output.shard_hash);
			let (deal_id, shard) = decode_shard(&encoded).unwrap();
			assert_eq!(deal_id, envelope.deal_id);
			if [0, 2, 4].contains(&index) {
				let path =
					holders.locate(&output.share_set_member).unwrap().unwrap();
				shards.insert(path, shard);
			}
		}

		let seed =
			open_quorum_key(&envelope, &output.quorum_key, &tree, &shards)
				.unwrap();
		assert_eq!(
			HybridPair::from_master_seed(&seed)
				.unwrap()
				.public_key()
				.to_bytes(),
			output.quorum_key
		);
	}

	#[test]
	fn genesis_refuses_an_invalid_tree_and_a_repeated_key() {
		let pair = HybridPair::generate().unwrap();
		let over = GenesisSet {
			members: vec![member(0, &pair)],
			threshold: 2,
			groups: vec![],
		};
		assert!(matches!(
			boot_genesis(&mut state("over"), &over, None),
			Err(ProtocolError::InvalidShareTree(_))
		));

		let twice = GenesisSet {
			members: vec![
				member(0, &pair),
				QuorumMember { alias: "alias-b".into(), ..member(1, &pair) },
			],
			threshold: 2,
			groups: vec![],
		};
		assert_eq!(
			boot_genesis(&mut state("twice"), &twice, None).unwrap_err(),
			ProtocolError::DuplicateQuorumMember
		);
	}

	#[test]
	fn genesis_wraps_the_seed_to_a_dr_key() {
		let member_pair = HybridPair::generate().unwrap();
		let dr_pair = HybridPair::generate().unwrap();
		let genesis_set = GenesisSet {
			members: vec![member(0, &member_pair)],
			threshold: 1,
			groups: vec![],
		};
		let (output, _) = boot_genesis(
			&mut state("dr"),
			&genesis_set,
			Some(dr_pair.public_key().to_bytes()),
		)
		.unwrap();
		let wrapped = dr_pair
			.decrypt(&output.dr_key_wrapped_quorum_key.unwrap())
			.unwrap();
		let seed: zeroize::Zeroizing<[u8; qos_hybrid::MASTER_SEED_LEN]> =
			zeroize::Zeroizing::new(wrapped[..].try_into().unwrap());
		assert_eq!(
			HybridPair::from_master_seed(&seed)
				.unwrap()
				.public_key()
				.to_bytes(),
			output.quorum_key
		);
	}
}
