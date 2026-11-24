//! Hierarchical Shamir secret sharing over a tree of threshold groups.
//!
//! Every node of a [`ShareTree`] splits its secret among its children with
//! [`crate::shamir`]: its member leaves first, then its subgroups, each child
//! taking the identifier one past its position. A member keeps its share
//! (`identifier || y`); a subgroup splits `y` again with fresh randomness. A
//! node with threshold 1 hands every child the secret itself. So every leaf
//! share is one byte longer than the secret, as in a flat split, and a tree
//! with no groups produces exactly the shares of [`crate::shamir`].
//!
//! Leaves are numbered depth first: a node's members, then the leaves of each
//! of its groups in order.

use zeroize::Zeroizing;

use crate::{QosCryptoError, shamir};

/// Deepest tree [`ShareTree::validate`] accepts; a flat share set has depth 1.
pub const MAX_SHARE_TREE_DEPTH: usize = 4;

/// Most children one node may have: a share identifier is one non-zero byte.
pub const MAX_SHARE_TREE_CHILDREN: usize = 255;

/// The shape of a hierarchical sharing. A node is satisfied once `threshold`
/// of its children are: a member leaf by its share, a group by its own
/// threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareTree {
	/// Children that must be satisfied to recover this node's secret.
	pub threshold: usize,
	/// Count of member leaves, which come before the groups.
	pub members: usize,
	/// Subgroups, each recovering one share of this node's secret.
	pub groups: Vec<ShareTree>,
}

impl ShareTree {
	/// A single node of `members` leaves: today's flat `threshold`-of-`members`
	/// share set.
	#[must_use]
	pub fn flat(threshold: usize, members: usize) -> Self {
		Self { threshold, members, groups: Vec::new() }
	}

	/// Count of member leaves in the whole tree.
	#[must_use]
	pub fn leaf_count(&self) -> usize {
		self.members + self.groups.iter().map(Self::leaf_count).sum::<usize>()
	}

	/// Check every node has `1 <= threshold <= children <= 255` and the tree is
	/// at most [`MAX_SHARE_TREE_DEPTH`] deep.
	///
	/// # Errors
	///
	/// Returns [`QosCryptoError::InvalidShareTree`] naming the first broken
	/// rule.
	pub fn validate(&self) -> Result<(), QosCryptoError> {
		self.validate_at(1)
	}

	fn validate_at(&self, depth: usize) -> Result<(), QosCryptoError> {
		if depth > MAX_SHARE_TREE_DEPTH {
			return Err(QosCryptoError::InvalidShareTree(
				"share tree is deeper than the maximum depth",
			));
		}
		let children = self.children();
		if children > MAX_SHARE_TREE_CHILDREN {
			return Err(QosCryptoError::InvalidShareTree(
				"a share tree node has more than 255 children",
			));
		}
		if self.threshold == 0 {
			return Err(QosCryptoError::InvalidShareTree(
				"a share tree node has a zero threshold",
			));
		}
		if self.threshold > children {
			return Err(QosCryptoError::InvalidShareTree(
				"a share tree node's threshold exceeds its children",
			));
		}
		self.groups.iter().try_for_each(|group| group.validate_at(depth + 1))
	}

	/// Whether the leaves marked in `present`, indexed depth first, satisfy
	/// the root.
	///
	/// # Errors
	///
	/// Returns [`QosCryptoError::ShareCountMismatch`] unless `present` has one
	/// entry per leaf.
	pub fn is_satisfied(
		&self,
		present: &[bool],
	) -> Result<bool, QosCryptoError> {
		if present.len() != self.leaf_count() {
			return Err(QosCryptoError::ShareCountMismatch);
		}
		Ok(self.satisfied(present))
	}

	fn satisfied(&self, present: &[bool]) -> bool {
		let (members, mut rest) = present.split_at(self.members);
		let mut satisfied = members.iter().filter(|present| **present).count();
		for group in &self.groups {
			let (leaves, tail) = rest.split_at(group.leaf_count());
			rest = tail;
			satisfied += usize::from(group.satisfied(leaves));
		}
		satisfied >= self.threshold
	}

	/// The identifier byte a share for `leaf`, indexed depth first, carries,
	/// or `None` past the last leaf.
	#[must_use]
	pub fn leaf_identifier(&self, leaf: usize) -> Option<u8> {
		if leaf < self.members {
			return u8::try_from(leaf + 1).ok();
		}
		let mut rest = leaf - self.members;
		for group in &self.groups {
			let count = group.leaf_count();
			if rest < count {
				return group.leaf_identifier(rest);
			}
			rest -= count;
		}
		None
	}

	fn children(&self) -> usize {
		self.members + self.groups.len()
	}
}

/// Split `secret` over `tree`, returning one share per leaf, depth first.
///
/// # Errors
///
/// Returns [`QosCryptoError::InvalidShareTree`] if `tree` fails
/// [`ShareTree::validate`], [`QosCryptoError::Vsss`] if a split fails.
pub fn tree_shares_generate(
	secret: &[u8],
	tree: &ShareTree,
) -> Result<Vec<Zeroizing<Vec<u8>>>, QosCryptoError> {
	tree.validate()?;
	if secret.is_empty() {
		return Err(QosCryptoError::Vsss(vsss_rs::Error::InvalidSecret));
	}
	let mut leaves = Vec::with_capacity(tree.leaf_count());
	split_node(secret, tree, &mut leaves)?;
	Ok(leaves)
}

fn split_node(
	secret: &[u8],
	node: &ShareTree,
	leaves: &mut Vec<Zeroizing<Vec<u8>>>,
) -> Result<(), QosCryptoError> {
	let children = node.children();
	let shares = if node.threshold == 1 {
		(1..=children)
			.map(|position| {
				let mut share =
					Zeroizing::new(Vec::with_capacity(secret.len() + 1));
				share.push(identifier(position - 1));
				share.extend_from_slice(secret);
				share
			})
			.collect()
	} else {
		shamir::shares_generate(secret, children, node.threshold)?
	};
	let mut shares = shares.into_iter();
	leaves.extend(shares.by_ref().take(node.members));
	for (group, share) in node.groups.iter().zip(shares) {
		split_node(&share[1..], group, leaves)?;
	}
	Ok(())
}

/// Recover the secret from `shares`, one optional share per leaf of `tree`,
/// depth first. Each node uses its first `threshold` satisfied children.
///
/// # Errors
///
/// - [`QosCryptoError::InvalidShareTree`] if `tree` fails
///   [`ShareTree::validate`];
/// - [`QosCryptoError::ShareCountMismatch`] unless `shares` has one entry per
///   leaf;
/// - [`QosCryptoError::ShareIdentifierMismatch`] if a share's identifier is
///   not its leaf's position;
/// - [`QosCryptoError::ShareLengthMismatch`] if shares differ in length or
///   carry no secret;
/// - [`QosCryptoError::ThresholdNotMet`] if the shares do not satisfy the
///   root;
/// - [`QosCryptoError::Vsss`] if a combine fails.
pub fn tree_shares_reconstruct(
	tree: &ShareTree,
	shares: &[Option<Zeroizing<Vec<u8>>>],
) -> Result<Zeroizing<Vec<u8>>, QosCryptoError> {
	tree.validate()?;
	if shares.len() != tree.leaf_count() {
		return Err(QosCryptoError::ShareCountMismatch);
	}
	let share_len = shares
		.iter()
		.flatten()
		.map(|share| share.len())
		.next()
		.ok_or(QosCryptoError::ThresholdNotMet)?;
	if share_len < 2 {
		return Err(QosCryptoError::ShareLengthMismatch);
	}
	recover_node(tree, shares, share_len)?
		.ok_or(QosCryptoError::ThresholdNotMet)
}

fn recover_node(
	node: &ShareTree,
	shares: &[Option<Zeroizing<Vec<u8>>>],
	share_len: usize,
) -> Result<Option<Zeroizing<Vec<u8>>>, QosCryptoError> {
	let (members, mut rest) = shares.split_at(node.members);
	let mut points: Vec<Zeroizing<Vec<u8>>> =
		Vec::with_capacity(node.threshold);

	for (position, share) in members.iter().enumerate() {
		let Some(share) = share else { continue };
		if share.len() != share_len {
			return Err(QosCryptoError::ShareLengthMismatch);
		}
		if share[0] != identifier(position) {
			return Err(QosCryptoError::ShareIdentifierMismatch);
		}
		if points.len() < node.threshold {
			points.push(share.clone());
		}
	}

	for (offset, group) in node.groups.iter().enumerate() {
		let (leaves, tail) = rest.split_at(group.leaf_count());
		rest = tail;
		let Some(secret) = recover_node(group, leaves, share_len)? else {
			continue;
		};
		if points.len() < node.threshold {
			let mut point = Zeroizing::new(Vec::with_capacity(share_len));
			point.push(identifier(node.members + offset));
			point.extend_from_slice(&secret);
			points.push(point);
		}
	}

	if points.len() < node.threshold {
		return Ok(None);
	}
	if node.threshold == 1 {
		return Ok(Some(Zeroizing::new(points[0][1..].to_vec())));
	}
	shamir::shares_reconstruct(&points).map(Some)
}

fn identifier(position: usize) -> u8 {
	u8::try_from(position + 1).expect(
		"validate caps a node at 255 children, so identifiers fit a byte",
	)
}

#[cfg(test)]
mod test {
	use super::*;

	const SECRET: &[u8; 32] = b"a 32 byte hybrid quorum key seed";

	fn present(tree: &ShareTree, mask: u32) -> Vec<bool> {
		(0..tree.leaf_count()).map(|leaf| mask & (1 << leaf) != 0).collect()
	}

	fn subset(
		shares: &[Zeroizing<Vec<u8>>],
		present: &[bool],
	) -> Vec<Option<Zeroizing<Vec<u8>>>> {
		shares
			.iter()
			.zip(present)
			.map(|(share, present)| present.then(|| share.clone()))
			.collect()
	}

	/// Reconstruct from every subset of leaves and demand it succeeds exactly
	/// where `expected` says the subset qualifies.
	fn assert_every_subset(
		tree: &ShareTree,
		expected: impl Fn(&[bool]) -> bool,
	) {
		let shares = tree_shares_generate(SECRET, tree).unwrap();
		assert_eq!(shares.len(), tree.leaf_count());
		assert!(shares.iter().all(|share| share.len() == SECRET.len() + 1));
		for (leaf, share) in shares.iter().enumerate() {
			assert_eq!(tree.leaf_identifier(leaf), Some(share[0]));
		}
		assert_eq!(tree.leaf_identifier(shares.len()), None);

		for mask in 0..(1u32 << tree.leaf_count()) {
			let present = present(tree, mask);
			let qualifies = expected(&present);
			assert_eq!(
				tree.is_satisfied(&present).unwrap(),
				qualifies,
				"is_satisfied disagrees with the access rule for leaves {present:?}"
			);
			let result =
				tree_shares_reconstruct(tree, &subset(&shares, &present));
			if qualifies {
				assert_eq!(
					&result.unwrap()[..],
					SECRET,
					"a qualifying subset {present:?} must recover the secret"
				);
			} else {
				assert_eq!(
					result,
					Err(QosCryptoError::ThresholdNotMet),
					"a non-qualifying subset {present:?} must not reconstruct"
				);
			}
		}
	}

	fn count(leaves: &[bool]) -> usize {
		leaves.iter().filter(|leaf| **leaf).count()
	}

	#[test]
	fn a_flat_tree_matches_the_flat_split() {
		let tree = ShareTree::flat(3, 5);
		let shares = tree_shares_generate(SECRET, &tree).unwrap();
		for (position, share) in shares.iter().enumerate() {
			assert_eq!(usize::from(share[0]), position + 1);
		}
		assert_eq!(
			&shamir::shares_reconstruct(&shares[1..4]).unwrap()[..],
			SECRET
		);
		assert_every_subset(&tree, |leaves| count(leaves) >= 3);
	}

	#[test]
	fn a_flat_tree_recovers_the_oldest_pinned_shares() {
		let shares = [
			"01661fc0cc265daa4e7bde354c281dcc23a80c590249",
			"027bb5fb26d326e0fc421cf604e495e3d3e4bd24ab0e",
			"0370d31b89800f2f9255abb73ca0ed0f8329d20fcc33",
		]
		.map(|hex| Some(Zeroizing::new(qos_hex::decode(hex).unwrap())));
		let tree = ShareTree::flat(2, 3);
		for missing in 0..3 {
			let mut subset = shares.clone();
			subset[missing] = None;
			assert_eq!(
				&tree_shares_reconstruct(&tree, &subset).unwrap()[..],
				b"my cute little secret"
			);
		}
	}

	#[test]
	fn two_organisations_both_required() {
		let tree = ShareTree {
			threshold: 2,
			members: 0,
			groups: vec![ShareTree::flat(3, 5), ShareTree::flat(2, 3)],
		};
		assert_every_subset(&tree, |leaves| {
			count(&leaves[..5]) >= 3 && count(&leaves[5..]) >= 2
		});
	}

	#[test]
	fn either_organisation_alone() {
		let tree = ShareTree {
			threshold: 1,
			members: 0,
			groups: vec![ShareTree::flat(3, 5), ShareTree::flat(2, 3)],
		};
		assert_every_subset(&tree, |leaves| {
			count(&leaves[..5]) >= 3 || count(&leaves[5..]) >= 2
		});
	}

	#[test]
	fn three_levels_with_mixed_children() {
		let external = ShareTree {
			threshold: 2,
			members: 0,
			groups: vec![ShareTree::flat(2, 3), ShareTree::flat(1, 2)],
		};
		let tree = ShareTree {
			threshold: 2,
			members: 1,
			groups: vec![ShareTree::flat(2, 3), external],
		};
		assert_eq!(tree.leaf_count(), 9);
		assert_every_subset(&tree, |leaves| {
			let lead = usize::from(leaves[0]);
			let umbra = usize::from(count(&leaves[1..4]) >= 2);
			let external = usize::from(
				count(&leaves[4..7]) >= 2 && count(&leaves[7..9]) >= 1,
			);
			lead + umbra + external >= 2
		});
	}

	#[test]
	fn a_threshold_one_node_hands_every_child_the_secret() {
		let tree = ShareTree::flat(1, 3);
		let shares = tree_shares_generate(SECRET, &tree).unwrap();
		for (position, share) in shares.iter().enumerate() {
			assert_eq!(usize::from(share[0]), position + 1);
			assert_eq!(&share[1..], SECRET);
		}
		assert_every_subset(&tree, |leaves| count(leaves) >= 1);
	}

	#[test]
	fn rejects_a_share_at_the_wrong_position() {
		let tree = ShareTree::flat(2, 3);
		let shares = tree_shares_generate(SECRET, &tree).unwrap();
		let swapped = [Some(shares[1].clone()), Some(shares[0].clone()), None];
		assert_eq!(
			tree_shares_reconstruct(&tree, &swapped),
			Err(QosCryptoError::ShareIdentifierMismatch)
		);
	}

	#[test]
	fn rejects_shares_of_different_lengths() {
		let tree = ShareTree::flat(2, 3);
		let shares = tree_shares_generate(SECRET, &tree).unwrap();
		let mut short = shares[1].clone();
		short.pop();
		let mixed = [Some(shares[0].clone()), Some(short), None];
		assert_eq!(
			tree_shares_reconstruct(&tree, &mixed),
			Err(QosCryptoError::ShareLengthMismatch)
		);
	}

	#[test]
	fn rejects_a_share_list_that_does_not_match_the_leaves() {
		let tree = ShareTree::flat(2, 3);
		let shares = tree_shares_generate(SECRET, &tree).unwrap();
		let short = [Some(shares[0].clone()), Some(shares[1].clone())];
		assert_eq!(
			tree_shares_reconstruct(&tree, &short),
			Err(QosCryptoError::ShareCountMismatch)
		);
		assert_eq!(
			tree.is_satisfied(&[true, true]),
			Err(QosCryptoError::ShareCountMismatch)
		);
	}

	#[test]
	fn validate_rejects_malformed_trees() {
		let zero = ShareTree::flat(0, 3);
		let over = ShareTree::flat(4, 3);
		let empty_group = ShareTree {
			threshold: 1,
			members: 1,
			groups: vec![ShareTree::flat(1, 0)],
		};
		let wide = ShareTree::flat(2, 256);
		let mut deep = ShareTree::flat(1, 1);
		for _ in 0..MAX_SHARE_TREE_DEPTH {
			deep = ShareTree { threshold: 1, members: 0, groups: vec![deep] };
		}
		for tree in [zero, over, empty_group, wide, deep] {
			assert!(
				matches!(
					tree.validate(),
					Err(QosCryptoError::InvalidShareTree(_))
				),
				"{tree:?} must fail validation"
			);
			assert!(tree_shares_generate(SECRET, &tree).is_err());
		}

		let mut deepest = ShareTree::flat(1, 1);
		for _ in 1..MAX_SHARE_TREE_DEPTH {
			deepest =
				ShareTree { threshold: 1, members: 0, groups: vec![deepest] };
		}
		deepest.validate().unwrap();
		let shares = tree_shares_generate(SECRET, &deepest).unwrap();
		assert_eq!(
			&tree_shares_reconstruct(&deepest, &[Some(shares[0].clone())])
				.unwrap()[..],
			SECRET
		);
	}

	#[test]
	fn the_widest_node_round_trips() {
		let tree = ShareTree::flat(2, MAX_SHARE_TREE_CHILDREN);
		let shares = tree_shares_generate(SECRET, &tree).unwrap();
		assert_eq!(shares[254][0], 255);
		let mut subset: Vec<_> = vec![None; MAX_SHARE_TREE_CHILDREN];
		subset[0] = Some(shares[0].clone());
		subset[254] = Some(shares[254].clone());
		assert_eq!(
			&tree_shares_reconstruct(&tree, &subset).unwrap()[..],
			SECRET
		);
	}
}
