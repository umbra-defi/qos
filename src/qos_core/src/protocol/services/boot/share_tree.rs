//! Share sets as holder trees.
//!
//! A share set is the top of a tree of threshold points over holders: it is satisfied once
//! `threshold` of its children are, its members first, then its groups, each satisfied by its own
//! threshold. The quorum key's master seed is sealed in a [`super::super::envelope`] whose key is
//! dealt down that tree, so holders recover the envelope key, never the seed itself.
//!
//! Two forms of the tree exist. Genesis and reshare take a [`GenesisSet`]-shaped tree of
//! [`ShareGroup`]s whose members carry their full hybrid keys, because each holder's shard is
//! sealed to its key. A manifest names only [`ShareHolder`]s: an alias and the two digests of the
//! key, as [`holder_digests`] computes them, so it commits to who holds a shard without carrying
//! 4224 bytes per member. Whoever posts a shard presents the full key, and its digests must match
//! a holder of the tree.
//!
//! [`GenesisSet`]: crate::protocol::services::genesis::GenesisSet

use std::collections::HashSet;

use qos_hybrid::{ENCRYPT_PUBLIC_LEN, HybridPublic};
use qos_nested_shamir::{DIGEST_BYTES, Holder, Node, Path, Point, Tree};
use sha3::{Digest, Sha3_384};

use crate::protocol::{
	ProtocolError,
	services::boot::{
		QuorumMember, ShareSet, ShareSetV2, ensure_unique_members,
	},
};

/// The domain a holder's receiving key (ML-KEM-1024 + X25519) is digested under.
pub const HOLDER_RECEIVING_KEY_DOMAIN: &[u8] =
	b"qos/share-holder/receiving-key/v1";

/// The domain a holder's signing key (ML-DSA-87 + Ed25519) is digested under.
pub const HOLDER_SIGNING_KEY_DOMAIN: &[u8] = b"qos/share-holder/signing-key/v1";

/// A threshold group of a genesis or reshare tree: one child of its parent, satisfied once
/// `threshold` of its own members and groups are. Members carry their full keys.
#[derive(
	PartialEq,
	Eq,
	Debug,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShareGroup {
	/// Human readable name, unique within the tree. Not cryptographically bound to anything.
	pub alias: String,
	/// Children of this group that must be satisfied.
	#[serde(with = "qos_json::string_or_numeric")]
	pub threshold: u32,
	/// Members holding a shard of this group's secret.
	#[serde(default)]
	pub members: Vec<QuorumMember>,
	/// Subgroups, each holding one share of this group's secret.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub groups: Vec<ShareGroup>,
}

/// A holder as a manifest names it: an alias and the digests of its two key halves.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShareHolder {
	/// Human readable name. Not cryptographically bound to anything.
	pub alias: String,
	/// [`holder_digests`]' receiving key digest, 48 bytes.
	#[serde(with = "qos_hex::serde")]
	pub receiving_key_digest: Vec<u8>,
	/// [`holder_digests`]' signing key digest, 48 bytes.
	#[serde(with = "qos_hex::serde")]
	pub signing_key_digest: Vec<u8>,
}

/// A threshold group of a manifest's share set, its members named by digest.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShareHolderGroup {
	/// Human readable name, unique within the share set.
	pub alias: String,
	/// Children of this group that must be satisfied.
	#[serde(with = "qos_json::string_or_numeric")]
	pub threshold: u32,
	/// Members holding a shard of this group's secret.
	#[serde(default)]
	pub members: Vec<ShareHolder>,
	/// Subgroups, each holding one share of this group's secret.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub groups: Vec<ShareHolderGroup>,
}

/// The receiving and signing key digests of a hybrid public key: each half, ML-KEM-1024 + X25519
/// then ML-DSA-87 + Ed25519, as SHA3-384 over its domain and the half, each preceded by its length
/// as an 8-byte big-endian integer.
///
/// # Errors
///
/// Returns a [`ProtocolError::HybridError`] when `public_key` is not a hybrid public key.
pub fn holder_digests(
	public_key: &[u8],
) -> Result<([u8; DIGEST_BYTES], [u8; DIGEST_BYTES]), ProtocolError> {
	let bytes = HybridPublic::from_bytes(public_key)?.to_bytes();
	let (receiving, signing) = bytes.split_at(ENCRYPT_PUBLIC_LEN);
	Ok((
		framed_digest(HOLDER_RECEIVING_KEY_DOMAIN, receiving),
		framed_digest(HOLDER_SIGNING_KEY_DOMAIN, signing),
	))
}

fn framed_digest(domain: &[u8], data: &[u8]) -> [u8; DIGEST_BYTES] {
	let mut hasher = Sha3_384::new();
	for part in [domain, data] {
		hasher.update((part.len() as u64).to_be_bytes());
		hasher.update(part);
	}
	hasher.finalize().into()
}

impl ShareHolder {
	/// The holder a member's key makes.
	///
	/// # Errors
	///
	/// As [`holder_digests`].
	pub fn from_member(member: &QuorumMember) -> Result<Self, ProtocolError> {
		let (receiving_key_digest, signing_key_digest) =
			holder_digests(&member.pub_key)?;
		Ok(Self {
			alias: member.alias.clone(),
			receiving_key_digest: receiving_key_digest.to_vec(),
			signing_key_digest: signing_key_digest.to_vec(),
		})
	}

	fn holder(&self) -> Result<Holder, ProtocolError> {
		let digest =
			|bytes: &[u8]| -> Result<[u8; DIGEST_BYTES], ProtocolError> {
				bytes.try_into().map_err(|_| {
					ProtocolError::InvalidShareTree(format!(
						"holder '{}' has a key digest that is not {DIGEST_BYTES} bytes",
						self.alias
					))
				})
			};
		Ok(Holder {
			receiving_key_digest: digest(&self.receiving_key_digest)?,
			signing_key_digest: digest(&self.signing_key_digest)?,
		})
	}
}

/// A node of a genesis or reshare tree, whose members carry full keys.
pub trait ShareNode {
	/// Children that must be satisfied to recover this node's secret.
	fn threshold(&self) -> u32;
	/// Members, which come before the groups.
	fn members(&self) -> &[QuorumMember];
	/// Subgroups.
	fn groups(&self) -> &[ShareGroup];

	/// Every member of the tree, depth first.
	fn leaves(&self) -> Vec<&QuorumMember> {
		let mut leaves: Vec<&QuorumMember> = self.members().iter().collect();
		for group in self.groups() {
			leaves.extend(group.leaves());
		}
		leaves
	}

	/// The tree as a manifest names it, without an envelope digest.
	///
	/// # Errors
	///
	/// As [`holder_digests`], for a member whose key is not a hybrid key.
	fn holder_set(&self) -> Result<ShareSetV2, ProtocolError> {
		Ok(ShareSetV2 {
			threshold: self.threshold(),
			members: self
				.members()
				.iter()
				.map(ShareHolder::from_member)
				.collect::<Result<_, _>>()?,
			groups: self
				.groups()
				.iter()
				.map(ShareGroup::holder_group)
				.collect::<Result<_, _>>()?,
			envelope_digest: None,
		})
	}

	/// Checks the tree can hold a quorum key: [`ShareHolderNode::tree`]'s limits, group aliases
	/// non-empty and unique, and no two members sharing an alias or a key component.
	///
	/// # Errors
	///
	/// [`ProtocolError::InvalidShareTree`] or [`ProtocolError::DuplicateQuorumMember`].
	fn validate(&self) -> Result<(), ProtocolError> {
		let leaves: Vec<QuorumMember> =
			self.leaves().into_iter().cloned().collect();
		ensure_unique_members(&leaves)?;
		self.holder_set()?.tree().map(|_| ())
	}
}

impl ShareGroup {
	fn holder_group(&self) -> Result<ShareHolderGroup, ProtocolError> {
		Ok(ShareHolderGroup {
			alias: self.alias.clone(),
			threshold: self.threshold,
			members: self
				.members
				.iter()
				.map(ShareHolder::from_member)
				.collect::<Result<_, _>>()?,
			groups: self
				.groups
				.iter()
				.map(ShareGroup::holder_group)
				.collect::<Result<_, _>>()?,
		})
	}
}

impl ShareNode for ShareGroup {
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

/// A node of a manifest's share set, whose members are named by digest.
pub trait ShareHolderNode {
	/// Children that must be satisfied to recover this node's secret.
	fn threshold(&self) -> u32;
	/// Members, which come before the groups.
	fn members(&self) -> &[ShareHolder];
	/// Subgroups.
	fn groups(&self) -> &[ShareHolderGroup];

	/// Whether the node has no threshold, members or groups: the share set of a manifest without
	/// a quorum key.
	fn is_empty(&self) -> bool {
		self.threshold() == 0
			&& self.members().is_empty()
			&& self.groups().is_empty()
	}

	/// The holder tree the envelope key is dealt over: each node a point whose children are its
	/// members, then its groups, child `i` having Shamir x-coordinate `i`. Group aliases must be
	/// non-empty and unique.
	///
	/// # Errors
	///
	/// [`ProtocolError::InvalidShareTree`] for a repeated or empty group alias, a threshold above
	/// 255, or a tree [`Tree::new`] refuses: a threshold outside 1 to its children, too many
	/// children, holders or levels, or a key digest appearing twice.
	fn tree(&self) -> Result<Tree, ProtocolError> {
		let mut aliases = HashSet::new();
		let top = point(self, &mut aliases)?;
		Tree::new(top)
			.map_err(|e| ProtocolError::InvalidShareTree(format!("{e:?}")))
	}

	/// The path of the holder whose key is `member`'s, or `None` when no holder's digests match.
	///
	/// # Errors
	///
	/// As [`Self::tree`] and [`holder_digests`].
	fn locate(
		&self,
		member: &QuorumMember,
	) -> Result<Option<Path>, ProtocolError> {
		let wanted = ShareHolder::from_member(member)?.holder()?;
		Ok(self
			.tree()?
			.holders()
			.into_iter()
			.find(|(_, holder)| **holder == wanted)
			.map(|(path, _)| path))
	}
}

fn point<N: ShareHolderNode + ?Sized>(
	node: &N,
	aliases: &mut HashSet<String>,
) -> Result<Point, ProtocolError> {
	let threshold = u8::try_from(node.threshold()).map_err(|_| {
		ProtocolError::InvalidShareTree(format!(
			"threshold {} is above 255",
			node.threshold()
		))
	})?;
	let mut children: Vec<Node> = node
		.members()
		.iter()
		.map(|member| member.holder().map(Node::Holder))
		.collect::<Result<_, _>>()?;
	for group in node.groups() {
		if group.alias.is_empty() {
			return Err(ProtocolError::InvalidShareTree(
				"a share group has an empty alias".to_string(),
			));
		}
		if !aliases.insert(group.alias.clone()) {
			return Err(ProtocolError::InvalidShareTree(format!(
				"share group alias '{}' appears more than once",
				group.alias
			)));
		}
		children.push(Node::Point(point(group, aliases)?));
	}
	Ok(Point { threshold, children })
}

impl ShareHolderNode for ShareHolderGroup {
	fn threshold(&self) -> u32 {
		self.threshold
	}
	fn members(&self) -> &[ShareHolder] {
		&self.members
	}
	fn groups(&self) -> &[ShareHolderGroup] {
		&self.groups
	}
}

impl ShareHolderNode for ShareSetV2 {
	fn threshold(&self) -> u32 {
		self.threshold
	}
	fn members(&self) -> &[ShareHolder] {
		&self.members
	}
	fn groups(&self) -> &[ShareHolderGroup] {
		&self.groups
	}
}

impl TryFrom<ShareSet> for ShareSetV2 {
	type Error = ProtocolError;

	/// A flat share set's members named by digest, with no envelope digest.
	fn try_from(flat: ShareSet) -> Result<Self, ProtocolError> {
		Ok(Self {
			threshold: flat.threshold,
			members: flat
				.members
				.iter()
				.map(ShareHolder::from_member)
				.collect::<Result<_, _>>()?,
			groups: vec![],
			envelope_digest: None,
		})
	}
}

#[cfg(test)]
mod test {
	use qos_hybrid::HybridPair;

	use super::*;
	use crate::protocol::services::{
		boot::manifest::canonical_json_hash, genesis::GenesisSet,
	};

	fn member(alias: &str) -> QuorumMember {
		QuorumMember {
			alias: alias.to_string(),
			pub_key: HybridPair::generate().unwrap().public_key().to_bytes(),
		}
	}

	fn group(
		alias: &str,
		threshold: u32,
		members: Vec<QuorumMember>,
	) -> ShareGroup {
		ShareGroup {
			alias: alias.to_string(),
			threshold,
			members,
			groups: vec![],
		}
	}

	fn two_organisations() -> GenesisSet {
		GenesisSet {
			threshold: 1,
			members: vec![],
			groups: vec![
				group(
					"umbra",
					2,
					vec![member("u0"), member("u1"), member("u2")],
				),
				group("external", 1, vec![member("e0"), member("e1")]),
			],
		}
	}

	#[test]
	fn an_empty_share_set_serializes_and_hashes_as_before() {
		let empty = ShareSetV2::default();
		assert_eq!(
			serde_json::to_string(&empty).unwrap(),
			r#"{"threshold":0,"members":[]}"#,
			"a manifest without a quorum key must keep its share set's JSON, or its hash moves"
		);
		assert!(empty.is_empty());
		let _ = canonical_json_hash(&empty);
	}

	#[test]
	fn a_manifest_names_holders_by_digest_and_round_trips() {
		let set = two_organisations().holder_set().unwrap();
		let json = serde_json::to_string(&set).unwrap();
		assert!(!json.contains("pubKey"), "a manifest carries no full key");
		assert_eq!(serde_json::from_str::<ShareSetV2>(&json).unwrap(), set);
		set.tree().unwrap();
	}

	#[test]
	fn locate_finds_a_member_by_its_key_digests_at_its_path() {
		let genesis = two_organisations();
		let set = genesis.holder_set().unwrap();
		let e1 = &genesis.groups[1].members[1];
		assert_eq!(set.locate(e1).unwrap(), Path::new(&[2, 2]));
		let u0 = &genesis.groups[0].members[0];
		assert_eq!(set.locate(u0).unwrap(), Path::new(&[1, 1]));
		assert_eq!(set.locate(&member("stranger")).unwrap(), None);
	}

	#[test]
	fn the_two_digests_cover_different_halves() {
		let key = HybridPair::generate().unwrap().public_key().to_bytes();
		let (receiving, signing) = holder_digests(&key).unwrap();
		assert_ne!(receiving, signing);
		assert!(holder_digests(&key[1..]).is_err());
	}

	#[test]
	fn validate_refuses_a_member_twice_and_a_repeated_alias() {
		let mut twice = two_organisations();
		let shared = twice.groups[0].members[0].clone();
		twice.groups[1]
			.members
			.push(QuorumMember { alias: "twin".into(), ..shared });
		assert_eq!(twice.validate(), Err(ProtocolError::DuplicateQuorumMember));

		let mut repeated = two_organisations();
		repeated.groups[1].alias = "umbra".to_string();
		assert!(matches!(
			repeated.validate(),
			Err(ProtocolError::InvalidShareTree(_))
		));

		let mut over = two_organisations();
		over.threshold = 3;
		assert!(matches!(
			over.validate(),
			Err(ProtocolError::InvalidShareTree(_))
		));

		two_organisations().validate().unwrap();
	}
}
