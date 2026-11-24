use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::commitment::{
	DealId, PointHint, RootCommitment, SECRET_BYTES, Secret, Shard, point_hint,
	root_commitment,
};
use crate::field;
use crate::{Node, Path, Point, Tree};

/// The most shares one search may feed into interpolations, summed over every interpolation it
/// runs, before it gives up with [`RebuildError::SearchExhausted`]. [`rebuild`] runs at most two
/// searches.
pub const MAX_SEARCH_SHARES: usize = 1 << 16;

/// The most distinct secrets a point without a hint passes up to its parent.
const MAX_CANDIDATES: usize = 16;

/// The most interpolations a point without a hint runs to rank its candidate secrets.
const MAX_UNHINTED_ATTEMPTS: usize = 64;

/// Why a rebuild found no secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebuildError {
	/// A shard is keyed by a path where the tree has no holder.
	ShardNotAtHolder {
		/// The shard's path.
		path: Path,
	},
	/// The holders whose shards were given do not satisfy the tree.
	NotSatisfied,
	/// The search spent [`MAX_SEARCH_SHARES`] without a secret matching the root commitment.
	SearchExhausted,
	/// Every combination of shares the search reached was tried and none rebuilt a secret matching
	/// the root commitment.
	NoMatch,
}

impl fmt::Display for RebuildError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ShardNotAtHolder { path } => {
				write!(
					formatter,
					"a shard is keyed by {path:?}, where the tree has no holder"
				)
			}
			Self::NotSatisfied => {
				formatter.write_str("the holders given do not satisfy the tree")
			}
			Self::SearchExhausted => formatter.write_str(
				"the search budget ran out before the root commitment matched",
			),
			Self::NoMatch => formatter.write_str(
				"no combination of shares matched the root commitment",
			),
		}
	}
}

impl std::error::Error for RebuildError {}

/// Rebuilds the secret dealt down `tree` from `shards`, bottom up, and returns it only when its
/// root commitment under `app_binding` is `expected`.
///
/// At each point the secret is interpolated at x = 0 from `t` children that have a value. When
/// `hints` holds the hint of a holder or point for `deal_id`, a shard or secret that does not
/// match it is skipped, and a point's subsets of `t` children are tried until one matches. A point
/// without a hint passes up the few secrets its subsets give most often, and the top point's
/// subsets are tried until one matches `expected`. Subsets are tried in lexicographic order of the
/// children they leave out, so a few bad shares are passed over early. Hints never decide: when
/// the search with them fails, the search runs again without them, and only `expected` decides.
/// Every intermediate secret is zeroed when dropped.
///
/// # Errors
///
/// - [`RebuildError::ShardNotAtHolder`] when a key of `shards` names no holder of `tree`.
/// - [`RebuildError::NotSatisfied`] when the holders in `shards` do not satisfy `tree`.
/// - [`RebuildError::SearchExhausted`] when a search spends [`MAX_SEARCH_SHARES`], which takes
///   many bad shares spread across wide points without hints.
/// - [`RebuildError::NoMatch`] when no combination reached matches `expected`: the shards are of
///   another secret, tree or binding, or too many of them are bad.
///
/// # Examples
///
/// [`deal`] shows a deal rebuilt from a satisfying set of shards.
pub fn rebuild(
	tree: &Tree,
	shards: &BTreeMap<Path, Shard>,
	hints: &BTreeMap<Path, PointHint>,
	app_binding: &[u8],
	deal_id: &DealId,
	expected: &RootCommitment,
) -> Result<Secret, RebuildError> {
	if let Some(path) = shards.keys().find(|path| tree.holder(path).is_none()) {
		return Err(RebuildError::ShardNotAtHolder { path: *path });
	}
	let present: BTreeSet<Path> = shards.keys().copied().collect();
	if !tree.is_satisfied_by(&present) {
		return Err(RebuildError::NotSatisfied);
	}
	let with_hints =
		Search { shards, hints, app_binding, deal_id }.run(tree, expected);
	match with_hints {
		Err(_) if !hints.is_empty() => {
			Search { shards, hints: &BTreeMap::new(), app_binding, deal_id }
				.run(tree, expected)
		}
		result => result,
	}
}

enum Flow {
	Continue,
	Stop,
}

struct Budget {
	remaining: usize,
	exhausted: bool,
}

struct Child {
	x: u8,
	candidates: Vec<Secret>,
}

struct Search<'context> {
	shards: &'context BTreeMap<Path, Shard>,
	hints: &'context BTreeMap<Path, PointHint>,
	app_binding: &'context [u8],
	deal_id: &'context DealId,
}

impl Search<'_> {
	fn run(
		&self,
		tree: &Tree,
		expected: &RootCommitment,
	) -> Result<Secret, RebuildError> {
		let mut budget =
			Budget { remaining: MAX_SEARCH_SHARES, exhausted: false };
		let children = self.children(tree.top(), Path::TOP, &mut budget);
		let mut found = None;
		for_each_interpolation(
			tree.top().threshold,
			&children,
			&mut budget,
			|secret| {
				if root_commitment(self.app_binding, secret) == *expected {
					found = Some(secret.clone());
					Flow::Stop
				} else {
					Flow::Continue
				}
			},
		);
		match found {
			Some(secret) => Ok(secret),
			None if budget.exhausted => Err(RebuildError::SearchExhausted),
			None => Err(RebuildError::NoMatch),
		}
	}

	fn children(
		&self,
		point: &Point,
		path: Path,
		budget: &mut Budget,
	) -> Vec<Child> {
		let mut children = Vec::new();
		for (child, x) in point.children.iter().zip(1u8..) {
			if budget.exhausted {
				break;
			}
			let child_path =
				path.child(x).expect("a validated tree has valid paths");
			let candidates = match child {
				Node::Holder(_) => self.holder_candidates(child_path),
				Node::Point(child) => {
					self.point_candidates(child, child_path, budget)
				}
			};
			if !candidates.is_empty() {
				children.push(Child { x, candidates });
			}
		}
		children
	}

	fn holder_candidates(&self, path: Path) -> Vec<Secret> {
		let Some(shard) = self.shards.get(&path) else {
			return Vec::new();
		};
		if !self.matches_hint(path, shard.expose()) {
			return Vec::new();
		}
		vec![Secret::new(*shard.expose())]
	}

	fn point_candidates(
		&self,
		point: &Point,
		path: Path,
		budget: &mut Budget,
	) -> Vec<Secret> {
		let children = self.children(point, path, budget);
		let hinted = self.hints.contains_key(&path);
		let mut tally: Vec<(Secret, usize)> = Vec::new();
		let mut attempts = 0;
		for_each_interpolation(point.threshold, &children, budget, |secret| {
			if hinted {
				if self.matches_hint(path, secret.expose()) {
					tally.push((secret.clone(), 1));
					return Flow::Stop;
				}
				return Flow::Continue;
			}
			attempts += 1;
			match tally.iter_mut().find(|(seen, _)| seen.ct_equals(secret)) {
				Some((_, count)) => *count += 1,
				None => tally.push((secret.clone(), 1)),
			}
			if attempts >= MAX_UNHINTED_ATTEMPTS {
				Flow::Stop
			} else {
				Flow::Continue
			}
		});
		tally.sort_by_key(|entry| core::cmp::Reverse(entry.1));
		tally.truncate(MAX_CANDIDATES);
		tally.into_iter().map(|(secret, _)| secret).collect()
	}

	fn matches_hint(&self, path: Path, secret: &[u8; SECRET_BYTES]) -> bool {
		self.hints.get(&path).is_none_or(|hint| {
			point_hint(self.app_binding, self.deal_id, &path, secret) == *hint
		})
	}
}

/// Interpolates at x = 0 every way of taking one candidate from each of `threshold` children,
/// subset by subset, until `visit` stops or the budget runs out.
///
/// Subsets are visited in lexicographic order of the children they leave out, so with one child
/// to spare each child is left out in turn, and a lone bad share is passed over early.
fn for_each_interpolation(
	threshold: u8,
	children: &[Child],
	budget: &mut Budget,
	mut visit: impl FnMut(&Secret) -> Flow,
) {
	let size = usize::from(threshold);
	if children.len() < size || budget.exhausted {
		return;
	}
	let mut left_out: Vec<usize> = (0..children.len() - size).collect();
	let mut chosen = vec![0usize; size];
	let mut xs = vec![0u8; size];
	let mut picks = vec![0usize; size];
	let mut value = Secret::zeroed();
	loop {
		let mut slot = 0;
		let mut skipped = 0;
		for (index, child) in children.iter().enumerate() {
			if left_out.get(skipped) == Some(&index) {
				skipped += 1;
			} else {
				chosen[slot] = index;
				xs[slot] = child.x;
				slot += 1;
			}
		}
		picks.fill(0);
		loop {
			if budget.remaining < size {
				budget.exhausted = true;
				return;
			}
			budget.remaining -= size;
			let ys: Vec<&[u8; SECRET_BYTES]> = chosen
				.iter()
				.zip(&picks)
				.map(|(&child, &pick)| {
					children[child].candidates[pick].expose()
				})
				.collect();
			field::interpolate(&xs, &ys, 0, value.bytes_mut());
			if let Flow::Stop = visit(&value) {
				return;
			}
			if !advance_picks(&mut picks, &chosen, children) {
				break;
			}
		}
		if !advance_combination(&mut left_out, children.len()) {
			return;
		}
	}
}

fn advance_picks(
	picks: &mut [usize],
	chosen: &[usize],
	children: &[Child],
) -> bool {
	for slot in (0..picks.len()).rev() {
		picks[slot] += 1;
		if picks[slot] < children[chosen[slot]].candidates.len() {
			return true;
		}
		picks[slot] = 0;
	}
	false
}

fn advance_combination(combination: &mut [usize], count: usize) -> bool {
	let size = combination.len();
	for position in (0..size).rev() {
		if combination[position] < count - size + position {
			combination[position] += 1;
			for later in position + 1..size {
				combination[later] = combination[later - 1] + 1;
			}
			return true;
		}
	}
	false
}
