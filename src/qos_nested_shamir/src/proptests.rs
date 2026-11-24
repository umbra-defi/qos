use std::collections::{BTreeMap, BTreeSet};

use proptest::collection::vec;
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use crate::field;
use crate::{
	DealId, Holder, MAX_HOLDERS, Node, Path, Point, RebuildError, SECRET_BYTES,
	Secret, Shard, Tree, deal, rebuild, root_commitment,
};

const APP_BINDING: &[u8] = b"umbra/nested-shamir/proptest";

#[derive(Clone, Debug)]
enum Shape {
	Holder,
	Point { threshold_seed: u8, children: Vec<Shape> },
}

fn shape() -> impl Strategy<Value = Shape> {
	Just(Shape::Holder).prop_recursive(3, 24, 4, |inner| {
		(any::<u8>(), vec(inner, 1..=4)).prop_map(
			|(threshold_seed, children)| Shape::Point {
				threshold_seed,
				children,
			},
		)
	})
}

fn tree() -> impl Strategy<Value = Tree> {
	(any::<u8>(), vec(shape(), 2..=4)).prop_filter_map(
		"the tree must fit the holder limit",
		|(threshold_seed, children)| {
			let mut number = 0u16;
			let children: Vec<Node> = children
				.iter()
				.map(|child| build(child, &mut number))
				.collect();
			let spare = u8::try_from(children.len() - 1)
				.expect("at most four children");
			let top = Point { threshold: 2 + threshold_seed % spare, children };
			if usize::from(number) > MAX_HOLDERS {
				return None;
			}
			Some(Tree::new(top).expect(
				"generated trees keep every limit but the holder count",
			))
		},
	)
}

fn build(shape: &Shape, number: &mut u16) -> Node {
	match shape {
		Shape::Holder => {
			*number += 1;
			let [high, low] = number.to_be_bytes();
			let mut receiving_key_digest = [0u8; 48];
			receiving_key_digest[..3].copy_from_slice(&[0x52, high, low]);
			let mut signing_key_digest = [0u8; 48];
			signing_key_digest[..3].copy_from_slice(&[0x53, high, low]);
			Node::Holder(Holder { receiving_key_digest, signing_key_digest })
		}
		Shape::Point { threshold_seed, children } => {
			let children: Vec<Node> =
				children.iter().map(|child| build(child, number)).collect();
			let count =
				u8::try_from(children.len()).expect("at most four children");
			Node::Point(Point {
				threshold: 1 + threshold_seed % count,
				children,
			})
		}
	}
}

fn secret() -> impl Strategy<Value = Secret> {
	vec(any::<u8>(), SECRET_BYTES).prop_map(|bytes| {
		Secret::new(
			bytes.try_into().expect("the strategy draws exactly 64 bytes"),
		)
	})
}

fn child_paths(
	point: &Point,
	path: Path,
) -> impl Iterator<Item = (u8, Path, &Node)> {
	point.children.iter().zip(1u8..).map(move |(child, x)| {
		let child_path =
			path.child(x).expect("a validated tree has valid paths");
		(x, child_path, child)
	})
}

fn node_satisfied(node: &Node, path: Path, present: &BTreeSet<Path>) -> bool {
	match node {
		Node::Holder(_) => present.contains(&path),
		Node::Point(point) => {
			child_paths(point, path)
				.filter(|(_, child_path, child)| {
					node_satisfied(child, *child_path, present)
				})
				.count() >= usize::from(point.threshold)
		}
	}
}

/// Returns the secret of the node at `path` in a complete deal, interpolated from its first
/// `threshold` children.
fn secret_of(
	node: &Node,
	path: Path,
	shards: &BTreeMap<Path, Shard>,
) -> [u8; SECRET_BYTES] {
	match node {
		Node::Holder(_) => *shards[&path].expose(),
		Node::Point(point) => {
			let (xs, ys): (Vec<u8>, Vec<[u8; SECRET_BYTES]>) =
				child_paths(point, path)
					.take(usize::from(point.threshold))
					.map(|(x, child_path, child)| {
						(x, secret_of(child, child_path, shards))
					})
					.unzip();
			let rows: Vec<&[u8; SECRET_BYTES]> = ys.iter().collect();
			let mut value = [0u8; SECRET_BYTES];
			field::interpolate(&xs, &rows, 0, &mut value);
			value
		}
	}
}

/// Returns, for every unsatisfied point with at least one satisfied child, whether interpolating
/// its satisfied children alone, the most an unsatisfying set can do there, gives its secret.
fn unsatisfied_points_leak(
	point: &Point,
	path: Path,
	shards: &BTreeMap<Path, Shard>,
	present: &BTreeSet<Path>,
) -> Vec<(Path, bool)> {
	let mut verdicts = Vec::new();
	let mut xs = Vec::new();
	let mut ys = Vec::new();
	for (x, child_path, child) in child_paths(point, path) {
		if node_satisfied(child, child_path, present) {
			xs.push(x);
			ys.push(secret_of(child, child_path, shards));
		} else if let Node::Point(child) = child {
			verdicts.extend(unsatisfied_points_leak(
				child, child_path, shards, present,
			));
		}
	}
	if !xs.is_empty() {
		let rows: Vec<&[u8; SECRET_BYTES]> = ys.iter().collect();
		let mut guess = [0u8; SECRET_BYTES];
		field::interpolate(&xs, &rows, 0, &mut guess);
		let own = secret_of(&Node::Point(point.clone()), path, shards);
		verdicts.push((path, guess == own));
	}
	verdicts
}

/// Writes into `out` a deal of `target` down the unsatisfied `point` that gives every holder in
/// `present` the shard it holds in `original`.
///
/// The satisfied children keep their original subtrees and so their secrets, which are fewer
/// than the threshold; with `target` at x = 0 and random values at the first unsatisfied children
/// they fix one polynomial of degree threshold − 1, and each unsatisfied child takes its value
/// and is dealt down again. Its existence for every target is what makes the shards of an
/// unsatisfying set independent of the root.
fn equivocate(
	point: &Point,
	path: Path,
	target: &[u8; SECRET_BYTES],
	original: &BTreeMap<Path, Shard>,
	present: &BTreeSet<Path>,
	randomness: &mut ChaCha20Rng,
	out: &mut BTreeMap<Path, Shard>,
) {
	let mut xs = vec![0u8];
	let mut ys = vec![*target];
	let mut unsatisfied = Vec::new();
	for (x, child_path, child) in child_paths(point, path) {
		if node_satisfied(child, child_path, present) {
			xs.push(x);
			ys.push(secret_of(child, child_path, original));
			for (holder_path, shard) in original {
				if holder_path.as_slice().starts_with(child_path.as_slice()) {
					out.insert(*holder_path, shard.clone());
				}
			}
		} else {
			unsatisfied.push((x, child_path, child));
		}
	}
	assert!(
		xs.len() <= usize::from(point.threshold),
		"an unsatisfied point has fewer satisfied children than its threshold"
	);
	for (x, _, _) in &unsatisfied[..usize::from(point.threshold) - xs.len()] {
		let mut value = [0u8; SECRET_BYTES];
		randomness.fill_bytes(&mut value);
		xs.push(*x);
		ys.push(value);
	}
	let rows: Vec<&[u8; SECRET_BYTES]> = ys.iter().collect();
	for (x, child_path, child) in unsatisfied {
		let mut value = [0u8; SECRET_BYTES];
		field::interpolate(&xs, &rows, x, &mut value);
		match child {
			Node::Holder(_) => {
				out.insert(child_path, Shard::new(value));
			}
			Node::Point(child) => equivocate(
				child, child_path, &value, original, present, randomness, out,
			),
		}
	}
}

proptest! {
	#[test]
	fn every_satisfying_set_rebuilds_the_root_and_no_other_set_learns_it(
		tree in tree(),
		root in secret(),
		other_root in secret(),
		seed in any::<[u8; 32]>(),
		mask in any::<u64>(),
	) {
		let deal_id = DealId(seed);
		let dealt = deal(&tree, &root, &mut ChaCha20Rng::from_seed(seed), APP_BINDING, &deal_id)
			.expect("a seeded ChaCha20 generator never fails");
		let present: BTreeSet<Path> = tree
			.holders()
			.iter()
			.enumerate()
			.filter(|(index, _)| mask >> index & 1 == 1)
			.map(|(_, (path, _))| *path)
			.collect();
		let shards: BTreeMap<Path, Shard> = present
			.iter()
			.map(|path| (*path, dealt.shards[path].clone()))
			.collect();
		let rebuilt = rebuild(
			&tree,
			&shards,
			&dealt.hints,
			APP_BINDING,
			&deal_id,
			&dealt.root_commitment,
		);

		if tree.is_satisfied_by(&present) {
			let rebuilt = rebuilt.expect("a satisfying set of honest shards rebuilds the root");
			prop_assert_eq!(
				rebuilt.expose(),
				root.expose(),
				"a satisfying set rebuilds exactly the dealt root"
			);
			return Ok(());
		}

		prop_assert_eq!(
			rebuilt.map(|_| ()),
			Err(RebuildError::NotSatisfied),
			"an unsatisfying set is refused before any interpolation"
		);
		for (path, leaked) in unsatisfied_points_leak(tree.top(), Path::TOP, &dealt.shards, &present) {
			prop_assert!(
				!leaked,
				"point {:?} is unsatisfied, so its satisfied children must not interpolate to its \
				 secret: each polynomial has degree threshold - 1",
				path
			);
		}
		prop_assume!(root.expose() != other_root.expose());
		let mut equivocal = BTreeMap::new();
		equivocate(
			tree.top(),
			Path::TOP,
			other_root.expose(),
			&dealt.shards,
			&present,
			&mut ChaCha20Rng::from_seed([seed[0] ^ 0xff; 32]),
			&mut equivocal,
		);
		for path in &present {
			prop_assert_eq!(
				equivocal[path].expose(),
				dealt.shards[path].expose(),
				"the other root's deal gives the unsatisfying set the very shards it holds"
			);
		}
		prop_assert_eq!(
			equivocal.len(),
			tree.holders().len(),
			"the other root's deal gives every holder a shard"
		);
		let other = rebuild(
			&tree,
			&equivocal,
			&BTreeMap::new(),
			APP_BINDING,
			&deal_id,
			&root_commitment(APP_BINDING, &other_root),
		)
		.expect("the equivocal shards are a complete deal of the other root");
		prop_assert_eq!(
			other.expose(),
			other_root.expose(),
			"the unsatisfying set's shards fit a deal of any root, so they reveal nothing about it"
		);
	}

	#[test]
	fn the_root_commitment_survives_every_redeal(
		tree in tree(),
		root in secret(),
		first_seed in any::<[u8; 32]>(),
		second_seed in any::<[u8; 32]>(),
	) {
		let first = deal(
			&tree,
			&root,
			&mut ChaCha20Rng::from_seed(first_seed),
			APP_BINDING,
			&DealId(first_seed),
		)
		.expect("a seeded ChaCha20 generator never fails");
		let second_id = DealId(second_seed);
		let second = deal(
			&tree,
			&root,
			&mut ChaCha20Rng::from_seed(second_seed),
			APP_BINDING,
			&second_id,
		)
		.expect("a seeded ChaCha20 generator never fails");
		prop_assert_eq!(
			first.root_commitment,
			second.root_commitment,
			"the root commitment names no deal, so every redeal pins the same value"
		);
		let rebuilt = rebuild(
			&tree,
			&second.shards,
			&second.hints,
			APP_BINDING,
			&second_id,
			&first.root_commitment,
		)
		.expect("a redeal rebuilds against the commitment pinned at the first deal");
		prop_assert_eq!(rebuilt.expose(), root.expose(), "the redeal rebuilds the same root");
	}
}
