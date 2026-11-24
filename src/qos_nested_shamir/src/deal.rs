use core::fmt;
use std::collections::BTreeMap;

use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::commitment::{
	DealId, PointHint, RootCommitment, SECRET_BYTES, Secret, Shard, point_hint,
	root_commitment,
};
use crate::field;
use crate::{Node, Path, Point, Tree};

/// What one deal hands out: a shard per holder, a hint per node and the root commitment.
#[derive(Debug)]
pub struct Deal {
	/// Each holder's shard, keyed by the holder's path.
	pub shards: BTreeMap<Path, Shard>,
	/// The hint of every node, the top point, every inner point and every holder, keyed by path.
	pub hints: BTreeMap<Path, PointHint>,
	/// The commitment to the dealt secret, the same on every deal of it under one binding.
	pub root_commitment: RootCommitment,
}

/// Why a deal failed.
#[derive(Debug)]
pub enum DealError {
	/// The randomness source failed to produce coefficients; nothing was handed out.
	Randomness(rand_core::Error),
}

impl fmt::Display for DealError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Randomness(error) => {
				write!(formatter, "the randomness source failed: {error}")
			}
		}
	}
}

impl std::error::Error for DealError {}

/// Deals `secret` down `tree`, top down, drawing fresh coefficients from `randomness` at every
/// point.
///
/// At a point with threshold `t` and `m` children, its secret is split byte by byte with Shamir
/// over GF(2^8) at x = 1 to `m`, under a random polynomial of degree `t − 1` per byte, and child
/// `i` takes the share at x = `i`. A holder's share is its shard. Fewer than `t` children of any
/// point learn nothing about its secret, so a set of holders that does not satisfy the tree learns
/// nothing about `secret` from its shards. The coefficients are drawn top down, depth first, in
/// child order, so the same tree, secret and randomness give the same deal.
///
/// `app_binding` and `deal_id` are bound into every hint; `app_binding` alone into the root
/// commitment.
///
/// # Errors
///
/// Returns [`DealError::Randomness`] when `randomness` fails.
///
/// # Examples
///
/// ```
/// use rand_core::OsRng;
/// use qos_nested_shamir::{DealId, Holder, Node, Point, Secret, Tree, deal, rebuild};
///
/// let holder = |byte: u8| {
///     Node::Holder(Holder {
///         receiving_key_digest: [byte; 48],
///         signing_key_digest: [byte | 0x80; 48],
///     })
/// };
/// let tree = Tree::new(Point {
///     threshold: 2,
///     children: vec![holder(1), holder(2), holder(3)],
/// })
/// .unwrap();
/// let root = Secret::new([9; 64]);
/// let deal_id = DealId([1; 32]);
/// let dealt = deal(&tree, &root, &mut OsRng, b"app", &deal_id).unwrap();
///
/// let mut shards = dealt.shards.clone();
/// shards.pop_first();
/// let rebuilt = rebuild(&tree, &shards, &dealt.hints, b"app", &deal_id, &dealt.root_commitment);
/// assert_eq!(rebuilt.unwrap().expose(), root.expose());
/// ```
pub fn deal(
	tree: &Tree,
	secret: &Secret,
	randomness: &mut impl CryptoRngCore,
	app_binding: &[u8],
	deal_id: &DealId,
) -> Result<Deal, DealError> {
	let mut dealer = Dealer {
		randomness,
		app_binding,
		deal_id,
		shards: BTreeMap::new(),
		hints: BTreeMap::new(),
	};
	dealer.point(tree.top(), Path::TOP, secret)?;
	Ok(Deal {
		shards: dealer.shards,
		hints: dealer.hints,
		root_commitment: root_commitment(app_binding, secret),
	})
}

struct Dealer<'context, Randomness> {
	randomness: &'context mut Randomness,
	app_binding: &'context [u8],
	deal_id: &'context DealId,
	shards: BTreeMap<Path, Shard>,
	hints: BTreeMap<Path, PointHint>,
}

impl<Randomness: CryptoRngCore> Dealer<'_, Randomness> {
	fn point(
		&mut self,
		point: &Point,
		path: Path,
		secret: &Secret,
	) -> Result<(), DealError> {
		self.hint(path, secret.expose());
		let degree = usize::from(point.threshold) - 1;
		let mut coefficients = Zeroizing::new(vec![0u8; SECRET_BYTES * degree]);
		self.randomness
			.try_fill_bytes(&mut coefficients)
			.map_err(DealError::Randomness)?;
		for (child, x) in point.children.iter().zip(1u8..) {
			let child_path =
				path.child(x).expect("a validated tree has valid paths");
			let mut share = Secret::zeroed();
			field::evaluate(
				secret.expose(),
				&coefficients,
				x,
				share.bytes_mut(),
			);
			match child {
				Node::Point(child) => self.point(child, child_path, &share)?,
				Node::Holder(_) => {
					self.hint(child_path, share.expose());
					self.shards.insert(child_path, Shard::new(*share.expose()));
				}
			}
		}
		Ok(())
	}

	fn hint(&mut self, path: Path, secret: &[u8; SECRET_BYTES]) {
		self.hints.insert(
			path,
			point_hint(self.app_binding, self.deal_id, &path, secret),
		);
	}
}
