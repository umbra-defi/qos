//! Share sets as holder trees.
//!
//! A share set is the top of a tree of threshold points over holders: it is satisfied once
//! `threshold` of its children are, its members first, then its groups, each satisfied by its own
//! threshold. The quorum key's master seed is sealed in a [`super::super::envelope`] whose key is
//! dealt down that tree, so holders recover the envelope key, never the seed itself.
//!
//! Two forms of the tree exist. Genesis and reshare take a [`GenesisSet`]-shaped tree of
//! [`ShareGroup`]s whose members carry their full hybrid keys, because each holder's shard is
//! sealed to its key. A manifest names only [`MemberDigest`]s: an alias and the two digests of the
//! key, as [`member_digests`] computes them, so it commits to who holds a shard without carrying
//! 4224 bytes per member. Whoever posts a shard presents the full key, and its digests must match
//! a holder of the tree.
//!
//! [`GenesisSet`]: crate::protocol::services::genesis::GenesisSet

use std::collections::{BTreeSet, HashSet};

use qos_hybrid::{ENCRYPT_PUBLIC_LEN, HybridPublic};
use qos_nested_shamir::{DIGEST_BYTES, Holder, Node, Path, Point, Tree};
use sha3::{Digest, Sha3_384};

use crate::protocol::{
	ProtocolError,
	services::boot::{
		ManifestSet, ManifestSetV2, QuorumMember, ShareSet, ShareSetV2,
		ensure_unique_members,
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

/// A key as a manifest names it: the digests of its two halves, as [`member_digests`] computes
/// them. The app key minter is named this way.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyDigests {
	/// The receiving key digest, 48 bytes.
	#[serde(with = "qos_hex::serde")]
	pub receiving_key_digest: Vec<u8>,
	/// The signing key digest, 48 bytes.
	#[serde(with = "qos_hex::serde")]
	pub signing_key_digest: Vec<u8>,
}

impl KeyDigests {
	/// The digests of `public_key`.
	///
	/// # Errors
	///
	/// As [`member_digests`].
	pub fn of(public_key: &[u8]) -> Result<Self, ProtocolError> {
		let (receiving, signing) = member_digests(public_key)?;
		Ok(Self {
			receiving_key_digest: receiving.to_vec(),
			signing_key_digest: signing.to_vec(),
		})
	}

	/// Whether `public_key` is a hybrid key whose digests these are.
	#[must_use]
	pub fn names(&self, public_key: &[u8]) -> bool {
		Self::of(public_key).is_ok_and(|digests| digests == *self)
	}
}

/// A member as a manifest names it, in its manifest set or as a holder of its share set: an alias
/// and the digests of its two key halves.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberDigest {
	/// Human readable name. Not cryptographically bound to anything.
	pub alias: String,
	/// [`member_digests`]' receiving key digest, 48 bytes.
	#[serde(with = "qos_hex::serde")]
	pub receiving_key_digest: Vec<u8>,
	/// [`member_digests`]' signing key digest, 48 bytes.
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
	pub members: Vec<MemberDigest>,
	/// Subgroups, each holding one share of this group's secret; `[]` when it has none.
	pub groups: Vec<ShareHolderGroup>,
}

/// The receiving and signing key digests of a hybrid public key: each half, ML-KEM-1024 + X25519
/// then ML-DSA-87 + Ed25519, as SHA3-384 over its domain and the half, each preceded by its length
/// as an 8-byte big-endian integer.
///
/// # Errors
///
/// Returns a [`ProtocolError::HybridError`] when `public_key` is not a hybrid public key.
pub fn member_digests(
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

impl MemberDigest {
	/// The holder a member's key makes.
	///
	/// # Errors
	///
	/// As [`member_digests`].
	pub fn from_member(member: &QuorumMember) -> Result<Self, ProtocolError> {
		let (receiving_key_digest, signing_key_digest) =
			member_digests(&member.pub_key)?;
		Ok(Self {
			alias: member.alias.clone(),
			receiving_key_digest: receiving_key_digest.to_vec(),
			signing_key_digest: signing_key_digest.to_vec(),
		})
	}

	/// Whether `member`'s key digests to this member's digests; the alias is not compared.
	#[must_use]
	pub fn names(&self, member: &QuorumMember) -> bool {
		KeyDigests {
			receiving_key_digest: self.receiving_key_digest.clone(),
			signing_key_digest: self.signing_key_digest.clone(),
		}
		.names(&member.pub_key)
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
	/// As [`member_digests`], for a member whose key is not a hybrid key.
	fn holder_set(&self) -> Result<ShareSetV2, ProtocolError> {
		Ok(ShareSetV2 {
			threshold: self.threshold(),
			members: self
				.members()
				.iter()
				.map(MemberDigest::from_member)
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
				.map(MemberDigest::from_member)
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
	fn members(&self) -> &[MemberDigest];
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

	/// Every member of the tree, depth first.
	fn holder_members(&self) -> Vec<&MemberDigest> {
		let mut out: Vec<&MemberDigest> = self.members().iter().collect();
		for group in self.groups() {
			out.extend(group.holder_members());
		}
		out
	}

	/// Checks the tree's limits as [`Self::tree`] does, every threshold from 1 to its node's
	/// children included, and that no two members anywhere in it share an alias or a key digest,
	/// so one key cannot count twice.
	///
	/// # Errors
	///
	/// [`ProtocolError::InvalidShareTree`], or [`ProtocolError::DuplicateQuorumMember`] for a
	/// repeated alias or digest.
	fn validate_holders(&self) -> Result<(), ProtocolError> {
		let mut aliases = HashSet::new();
		let mut digests = HashSet::new();
		for member in self.holder_members() {
			if !aliases.insert(&member.alias)
				|| !digests.insert(&member.receiving_key_digest)
				|| !digests.insert(&member.signing_key_digest)
			{
				return Err(ProtocolError::DuplicateQuorumMember);
			}
		}
		self.tree().map(|_| ())
	}

	/// Whether `members` satisfy the tree: each placed by its key's digests at one holder, a group
	/// satisfied once `threshold` of its members and groups are, and the top likewise. A member
	/// the tree does not name counts for nothing, and one named twice counts once.
	///
	/// # Errors
	///
	/// As [`Self::tree`].
	fn is_satisfied_by_members<'a>(
		&self,
		members: impl IntoIterator<Item = &'a QuorumMember>,
	) -> Result<bool, ProtocolError> {
		let tree = self.tree()?;
		let mut present = BTreeSet::new();
		for member in members {
			if let Ok(Some(path)) = self.locate(member) {
				present.insert(path);
			}
		}
		Ok(tree.is_satisfied_by(&present))
	}

	/// The path of the holder whose key is `member`'s, or `None` when no holder's digests match.
	///
	/// # Errors
	///
	/// As [`Self::tree`] and [`member_digests`].
	fn locate(
		&self,
		member: &QuorumMember,
	) -> Result<Option<Path>, ProtocolError> {
		let wanted = MemberDigest::from_member(member)?.holder()?;
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
	fn members(&self) -> &[MemberDigest] {
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
	fn members(&self) -> &[MemberDigest] {
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
				.map(MemberDigest::from_member)
				.collect::<Result<_, _>>()?,
			groups: vec![],
			envelope_digest: None,
		})
	}
}

impl TryFrom<&ManifestSet> for ManifestSetV2 {
	type Error = ProtocolError;

	/// A full-key manifest set's members named by digest, with no groups.
	fn try_from(set: &ManifestSet) -> Result<Self, ProtocolError> {
		Ok(Self {
			threshold: set.threshold,
			members: set
				.members
				.iter()
				.map(MemberDigest::from_member)
				.collect::<Result<_, _>>()?,
			groups: vec![],
		})
	}
}

impl ShareHolderNode for ManifestSetV2 {
	fn threshold(&self) -> u32 {
		self.threshold
	}
	fn members(&self) -> &[MemberDigest] {
		&self.members
	}
	fn groups(&self) -> &[ShareHolderGroup] {
		&self.groups
	}
}

impl ManifestSetV2 {
	/// The manifest set a full-key tree names: its members by digest, its groups as they are.
	///
	/// # Errors
	///
	/// As [`member_digests`], for a member whose key is not a hybrid key.
	pub fn from_tree<N: ShareNode>(tree: &N) -> Result<Self, ProtocolError> {
		let holders = tree.holder_set()?;
		Ok(Self {
			threshold: holders.threshold,
			members: holders.members,
			groups: holders.groups,
		})
	}

	/// Checks the set as [`ShareHolderNode::validate_holders`] does.
	///
	/// # Errors
	///
	/// As [`ShareHolderNode::validate_holders`].
	pub fn validate(&self) -> Result<(), ProtocolError> {
		self.validate_holders()
	}

	/// The set with every node's members sorted by digest and groups sorted by alias,
	/// recursively: two manifests name the same set exactly when these are equal.
	#[must_use]
	pub fn normalised(&self) -> Self {
		Self {
			threshold: self.threshold,
			members: normalised_members(&self.members),
			groups: normalised_groups(&self.groups),
		}
	}
}

fn normalised_members(members: &[MemberDigest]) -> Vec<MemberDigest> {
	let mut members = members.to_vec();
	members.sort_by(|left, right| {
		(&left.signing_key_digest, &left.receiving_key_digest)
			.cmp(&(&right.signing_key_digest, &right.receiving_key_digest))
	});
	members
}

fn normalised_groups(groups: &[ShareHolderGroup]) -> Vec<ShareHolderGroup> {
	let mut groups: Vec<ShareHolderGroup> = groups
		.iter()
		.map(|group| ShareHolderGroup {
			alias: group.alias.clone(),
			threshold: group.threshold,
			members: normalised_members(&group.members),
			groups: normalised_groups(&group.groups),
		})
		.collect();
	groups.sort_by(|left, right| left.alias.cmp(&right.alias));
	groups
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
	fn every_set_names_its_groups_even_when_it_has_none() {
		let empty = ShareSetV2::default();
		assert_eq!(
			serde_json::to_string(&empty).unwrap(),
			r#"{"threshold":0,"members":[],"groups":[]}"#,
		);
		assert!(empty.is_empty());
		let _ = canonical_json_hash(&empty);
		let flat = ManifestSetV2::try_from(&ManifestSet {
			threshold: 1,
			members: vec![member("u0")],
		})
		.unwrap();
		assert!(
			serde_json::to_string(&flat).unwrap().ends_with(r#""groups":[]}"#),
			"a flat manifest set must say it has no groups, not leave them out"
		);
		for json in [
			r#"{"threshold":0,"members":[]}"#,
			r#"{"threshold":"1","members":[]}"#,
		] {
			assert!(
				serde_json::from_str::<ShareSetV2>(json).is_err()
					&& serde_json::from_str::<ManifestSetV2>(json).is_err(),
				"a set without groups is not a 0.20 set: {json}"
			);
		}
	}

	/// Umbra (2 of u0, u1, u2) and either external team (ext1: a0 or a1; ext2: b0), both needed.
	fn manifest_tree() -> (ManifestSetV2, Vec<QuorumMember>) {
		let people: Vec<QuorumMember> = ["u0", "u1", "u2", "a0", "a1", "b0"]
			.iter()
			.map(|alias| member(alias))
			.collect();
		let tree = GenesisSet {
			threshold: 2,
			members: vec![],
			groups: vec![
				group("umbra", 2, people[0..3].to_vec()),
				ShareGroup {
					alias: "external".to_string(),
					threshold: 1,
					members: vec![],
					groups: vec![
						group("ext1", 1, people[3..5].to_vec()),
						group("ext2", 1, people[5..6].to_vec()),
					],
				},
			],
		};
		(ManifestSetV2::from_tree(&tree).unwrap(), people)
	}

	#[test]
	fn manifest_approvals_must_satisfy_the_tree() {
		let (set, people) = manifest_tree();
		set.validate().unwrap();
		let approved = |picks: &[usize]| {
			set.is_satisfied_by_members(picks.iter().map(|i| &people[*i]))
				.unwrap()
		};
		assert!(approved(&[0, 1, 3]), "two of Umbra and ext1");
		assert!(approved(&[2, 0, 5]), "two of Umbra and ext2");
		assert!(!approved(&[0, 1, 2]), "Umbra alone");
		assert!(!approved(&[0, 3, 5]), "one of Umbra and both teams");
		assert!(!approved(&[0, 0, 3]), "one Umbra member counted twice");
		let stranger = member("x");
		assert!(
			!set.is_satisfied_by_members([&people[0], &stranger, &people[3]])
				.unwrap(),
			"a stranger counts for nothing"
		);
	}

	#[test]
	fn a_manifest_set_threshold_must_be_from_one_to_its_children() {
		let (mut set, _) = manifest_tree();
		set.groups[0].threshold = 0;
		assert!(set.validate().is_err(), "threshold 0");
		let (mut set, _) = manifest_tree();
		set.groups[1].threshold = 3;
		assert!(set.validate().is_err(), "threshold above the children");
		let (mut set, people) = manifest_tree();
		set.groups[1].groups[0]
			.members
			.push(MemberDigest::from_member(&people[0]).unwrap());
		assert_eq!(set.validate(), Err(ProtocolError::DuplicateQuorumMember));
	}

	#[test]
	fn a_manifest_set_normalises_to_one_form_in_any_order() {
		let (set, _) = manifest_tree();
		let mut reordered = set.clone();
		reordered.groups.reverse();
		reordered.groups[1].members.reverse();
		assert_ne!(reordered, set);
		assert_eq!(reordered.normalised(), set.normalised());
		assert_eq!(
			reordered.normalised().tree().unwrap().digest(),
			set.normalised().tree().unwrap().digest()
		);
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
		let (receiving, signing) = member_digests(&key).unwrap();
		assert_ne!(receiving, signing);
		assert!(member_digests(&key[1..]).is_err());
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
