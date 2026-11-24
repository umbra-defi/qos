//! Share sets as trees of threshold groups.
//!
//! A share set is the root of a tree: it recovers the quorum key once
//! `threshold` of its children are satisfied, its members first, then its
//! [`ShareGroup`]s, each satisfied by its own threshold. A share set with no
//! groups is today's flat `threshold`-of-`members` set. Leaves are the
//! members, numbered depth first as [`qos_crypto::share_tree`] numbers them.

use std::collections::HashSet;

use qos_crypto::share_tree::ShareTree;

use crate::protocol::{
	ProtocolError,
	services::boot::{QuorumMember, ensure_unique_members},
};

/// A threshold group inside a share set: one child of its parent, satisfied
/// once `threshold` of its own members and groups are.
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
	/// Human readable name, unique within the share set. Not
	/// cryptographically bound to anything.
	pub alias: String,
	/// Children of this group that must be satisfied.
	#[serde(with = "qos_json::string_or_numeric")]
	pub threshold: u32,
	/// Members holding a share of this group's secret.
	#[serde(default)]
	pub members: Vec<QuorumMember>,
	/// Subgroups, each recovering one share of this group's secret.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub groups: Vec<ShareGroup>,
}

/// A node of a share tree: a share set, a [`ShareGroup`] or a genesis set.
pub trait ShareNode {
	/// Children that must be satisfied to recover this node's secret.
	fn threshold(&self) -> u32;
	/// Member leaves, which come before the groups.
	fn members(&self) -> &[QuorumMember];
	/// Subgroups.
	fn groups(&self) -> &[ShareGroup];

	/// The tree's shape, as [`qos_crypto::share_tree`] splits and recovers
	/// over it.
	fn shape(&self) -> ShareTree {
		ShareTree {
			threshold: self.threshold() as usize,
			members: self.members().len(),
			groups: self.groups().iter().map(ShareNode::shape).collect(),
		}
	}

	/// Every member of the tree, depth first: the order of the shape's
	/// leaves.
	fn leaves(&self) -> Vec<&QuorumMember> {
		let mut leaves: Vec<&QuorumMember> = self.members().iter().collect();
		for group in self.groups() {
			leaves.extend(group.leaves());
		}
		leaves
	}

	/// The depth-first leaf index of `member`, or `None` if it is not in the
	/// tree.
	fn leaf_index(&self, member: &QuorumMember) -> Option<usize> {
		self.leaves().into_iter().position(|leaf| leaf == member)
	}

	/// Whether `member` is anywhere in the tree.
	fn contains(&self, member: &QuorumMember) -> bool {
		self.leaf_index(member).is_some()
	}

	/// Whether the tree has no threshold, members or groups: the share set of
	/// a manifest without a quorum key.
	fn is_empty(&self) -> bool {
		self.threshold() == 0
			&& self.members().is_empty()
			&& self.groups().is_empty()
	}

	/// Check the tree can hold a quorum key: every node has
	/// `1 <= threshold <= children <= 255`, the tree is at most
	/// [`qos_crypto::share_tree::MAX_SHARE_TREE_DEPTH`] deep, group aliases
	/// are non-empty and unique, and no two members share an alias or a key
	/// component.
	///
	/// # Errors
	///
	/// Returns [`ProtocolError::InvalidShareTree`] for a broken shape or
	/// alias, [`ProtocolError::DuplicateQuorumMember`] for repeated members.
	fn validate(&self) -> Result<(), ProtocolError> {
		self.shape()
			.validate()
			.map_err(|e| ProtocolError::InvalidShareTree(format!("{e:?}")))?;
		let mut aliases = HashSet::new();
		ensure_unique_group_aliases(self.groups(), &mut aliases)?;
		let leaves: Vec<QuorumMember> =
			self.leaves().into_iter().cloned().collect();
		ensure_unique_members(&leaves)
	}
}

fn ensure_unique_group_aliases<'a>(
	groups: &'a [ShareGroup],
	aliases: &mut HashSet<&'a str>,
) -> Result<(), ProtocolError> {
	for group in groups {
		if group.alias.is_empty() {
			return Err(ProtocolError::InvalidShareTree(
				"a share group has an empty alias".to_string(),
			));
		}
		if !aliases.insert(&group.alias) {
			return Err(ProtocolError::InvalidShareTree(format!(
				"share group alias '{}' appears more than once",
				group.alias
			)));
		}
		ensure_unique_group_aliases(&group.groups, aliases)?;
	}
	Ok(())
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

#[cfg(test)]
mod test {
	use qos_hybrid::HybridPair;

	use super::*;
	use crate::protocol::services::boot::{
		ShareSet, ShareSetV2, manifest::canonical_json_hash,
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

	fn two_organisations() -> ShareSetV2 {
		ShareSetV2 {
			threshold: 2,
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
	fn a_flat_share_set_serializes_and_hashes_as_before() {
		let flat =
			ShareSet { threshold: 2, members: vec![member("a"), member("b")] };
		let tree = ShareSetV2::from(flat.clone());
		assert_eq!(
			serde_json::to_value(&tree).unwrap(),
			serde_json::to_value(&flat).unwrap(),
			"a share set without groups must keep the flat JSON, or every flat v2 manifest changes hash"
		);
		assert_eq!(canonical_json_hash(&tree), canonical_json_hash(&flat));
	}

	#[test]
	fn groups_round_trip_through_json() {
		let tree = two_organisations();
		let json = serde_json::to_string(&tree).unwrap();
		assert!(json.contains("\"groups\""));
		assert_eq!(serde_json::from_str::<ShareSetV2>(&json).unwrap(), tree);
	}

	#[test]
	fn unknown_group_fields_are_refused() {
		let json = r#"{"threshold":1,"members":[],"groups":[{"alias":"a","threshold":1,"members":[],"weight":2}]}"#;
		assert!(serde_json::from_str::<ShareSetV2>(json).is_err());
	}

	#[test]
	fn leaves_run_depth_first() {
		let mut tree = two_organisations();
		tree.members.push(member("lead"));
		let aliases: Vec<_> =
			tree.leaves().into_iter().map(|m| m.alias.as_str()).collect();
		assert_eq!(aliases, ["lead", "u0", "u1", "u2", "e0", "e1"]);
		assert_eq!(tree.shape().leaf_count(), 6);
		assert_eq!(
			tree.leaf_index(tree.groups[1].members.first().unwrap()),
			Some(4)
		);
	}

	#[test]
	fn validate_accepts_two_organisations() {
		two_organisations().validate().unwrap();
	}

	#[test]
	fn validate_refuses_a_member_in_two_groups() {
		let mut tree = two_organisations();
		let shared = tree.groups[0].members[0].clone();
		tree.groups[1].members.push(shared);
		assert_eq!(tree.validate(), Err(ProtocolError::DuplicateQuorumMember));
	}

	#[test]
	fn validate_refuses_one_key_under_two_aliases() {
		let mut tree = two_organisations();
		let mut twin = tree.groups[0].members[0].clone();
		twin.alias = "twin".to_string();
		tree.groups[1].members.push(twin);
		assert_eq!(tree.validate(), Err(ProtocolError::DuplicateQuorumMember));
	}

	#[test]
	fn validate_refuses_repeated_or_empty_group_aliases() {
		let mut repeated = two_organisations();
		repeated.groups[1].alias = "umbra".to_string();
		let mut nested = two_organisations();
		nested.groups[1].groups.push(group("umbra", 1, vec![member("n0")]));
		let mut empty = two_organisations();
		empty.groups[0].alias = String::new();
		for tree in [repeated, nested, empty] {
			assert!(matches!(
				tree.validate(),
				Err(ProtocolError::InvalidShareTree(_))
			));
		}
	}

	#[test]
	fn validate_refuses_a_threshold_above_the_children() {
		let mut tree = two_organisations();
		tree.threshold = 3;
		assert!(matches!(
			tree.validate(),
			Err(ProtocolError::InvalidShareTree(_))
		));
	}

	#[test]
	fn an_empty_share_set_is_empty() {
		assert!(ShareSetV2::default().is_empty());
		assert!(!two_organisations().is_empty());
	}
}
