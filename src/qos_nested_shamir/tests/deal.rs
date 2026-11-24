//! Dealing and rebuilding over trees, end to end.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{chain, design_example, holders, path, point};
use qos_nested_shamir::{
	Deal, DealError, DealId, MAX_DEPTH, MAX_HOLDERS, Path, Point, PointHint,
	RebuildError, Secret, Shard, Tree, deal, point_hint, rebuild,
	root_commitment,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

const APP_BINDING: &[u8] = b"umbra/guardian-share-node/test-binding";

fn root() -> Secret {
	let mut bytes = [0u8; 64];
	for (byte, value) in bytes.iter_mut().zip(0u8..) {
		*byte = value.wrapping_mul(37) ^ 0x5a;
	}
	Secret::new(bytes)
}

fn deal_seeded(
	tree: &Tree,
	secret: &Secret,
	seed: u8,
	deal_id: &DealId,
) -> Deal {
	deal(
		tree,
		secret,
		&mut ChaCha20Rng::from_seed([seed; 32]),
		APP_BINDING,
		deal_id,
	)
	.expect("a seeded ChaCha20 generator never fails")
}

fn rebuild_from(
	tree: &Tree,
	dealt: &Deal,
	shards: &BTreeMap<Path, Shard>,
	hints: &BTreeMap<Path, PointHint>,
	deal_id: &DealId,
) -> Result<Secret, RebuildError> {
	rebuild(tree, shards, hints, APP_BINDING, deal_id, &dealt.root_commitment)
}

fn only(dealt: &Deal, paths: &[Path]) -> BTreeMap<Path, Shard> {
	paths.iter().map(|path| (*path, dealt.shards[path].clone())).collect()
}

fn corrupt(shards: &mut BTreeMap<Path, Shard>, at: Path) {
	let mut bytes = *shards[&at].expose();
	let salt = at
		.as_slice()
		.iter()
		.fold(0u8, |salt, index| salt.wrapping_mul(31) ^ index);
	for (byte, position) in bytes.iter_mut().zip(0u8..) {
		*byte ^= (position.wrapping_mul(7) ^ salt.wrapping_mul(13)) | 1;
	}
	shards.insert(at, Shard::new(bytes));
}

fn no_hints() -> BTreeMap<Path, PointHint> {
	BTreeMap::new()
}

#[test]
fn deals_are_fixed_vectors() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let deal_id = DealId([0x11; 32]);
	let dealt = deal_seeded(&tree, &root(), 7, &deal_id);
	assert_eq!(
		hex::encode(dealt.root_commitment.0),
		"c9bd3fc2e0af105a715b9fc5d71d3947e0646078cab0dda58703cf3fdcee1cb8abe9bb40bc206c00c8c7331e74cb39dc",
		"the root commitment of the fixed root under the fixed binding is a fixed vector"
	);
	assert_eq!(
		hex::encode(dealt.shards[&path(&[1, 1])].expose()),
		"1d5a89b42b4dda9d3a22a48fef85d37d5664c32689e3533605eb654d985e6ef6c36fa44bb4d39974ac2954d18cca6a664e4c13ee4a391628b1ea9caf7a54680a",
		"the first Umbra holder's shard under seed 7 is a fixed vector"
	);
	assert_eq!(
		hex::encode(dealt.shards[&path(&[2, 3, 2])].expose()),
		"85a08aab40066e29086beb8032f3eb31fd15bc6909d1286ba6848146c7abb6111912a2694a9e785b8a9914ced8bb7d7b0c559376e04c0037666d346ee16b2f9a",
		"Org C's second holder's shard under seed 7 is a fixed vector"
	);
	assert_eq!(
		hex::encode(dealt.hints[&path(&[2])].0),
		"a66c0a2fddb4c6c84717c97ac67a894a2f084608561e936a036db7c02ee5cfa0ab087d3ae349984c52e6d018c824e8f9",
		"the externals' point hint under seed 7 and deal 0x11.. is a fixed vector"
	);
	assert_eq!(
		hex::encode(tree.digest().0),
		"71e16bd91ea92e610f301c2976ec56bba7da8e02e045bea6d8b9530088f6add10485147b13e75840807b16a805362ab9",
		"the design example's tree digest is a fixed vector"
	);
}

#[test]
fn the_same_seed_gives_the_same_deal_and_another_seed_gives_fresh_shards() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let deal_id = DealId([0x22; 32]);
	let first = deal_seeded(&tree, &root(), 1, &deal_id);
	let again = deal_seeded(&tree, &root(), 1, &deal_id);
	let other = deal_seeded(&tree, &root(), 2, &deal_id);
	for (path, shard) in &first.shards {
		assert_eq!(
			shard.expose(),
			again.shards[path].expose(),
			"the randomness source is the only randomness, so a seed fixes shard {path:?}"
		);
		assert_ne!(
			shard.expose(),
			other.shards[path].expose(),
			"every point draws fresh coefficients, so a new seed moves shard {path:?}"
		);
	}
}

#[test]
fn the_root_commitment_is_the_same_across_two_deals_of_one_root() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let first_id = DealId([0x01; 32]);
	let second_id = DealId([0x02; 32]);
	let first = deal_seeded(&tree, &root(), 3, &first_id);
	let second = deal_seeded(&tree, &root(), 4, &second_id);
	assert_eq!(
		first.root_commitment, second.root_commitment,
		"the root commitment names no deal, so a reshare rebuilds to the same pinned value"
	);
	assert_eq!(
		first.root_commitment,
		root_commitment(APP_BINDING, &root()),
		"a deal's root commitment is root_commitment of the dealt secret"
	);
	assert_ne!(
		first.hints[&Path::TOP],
		second.hints[&Path::TOP],
		"hints name the deal, so the top point's hint differs between deals of one root"
	);
	let rebuilt =
		rebuild_from(&tree, &second, &second.shards, &second.hints, &second_id)
			.expect("every shard of the second deal is present and honest");
	assert_eq!(
		root_commitment(APP_BINDING, &rebuilt),
		first.root_commitment,
		"the second deal rebuilds to the commitment pinned at the first"
	);
}

#[test]
fn every_holder_set_of_the_design_example_rebuilds_exactly_when_it_satisfies_the_tree()
 {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let deal_id = DealId([0x33; 32]);
	let dealt = deal_seeded(&tree, &root(), 5, &deal_id);
	let paths: Vec<Path> =
		tree.holders().iter().map(|(path, _)| *path).collect();
	for mask in 0u32..1 << paths.len() {
		let chosen: Vec<Path> = paths
			.iter()
			.enumerate()
			.filter(|(index, _)| mask >> index & 1 == 1)
			.map(|(_, path)| *path)
			.collect();
		let present: BTreeSet<Path> = chosen.iter().copied().collect();
		let result = rebuild_from(
			&tree,
			&dealt,
			&only(&dealt, &chosen),
			&dealt.hints,
			&deal_id,
		);
		if tree.is_satisfied_by(&present) {
			let rebuilt = result
				.expect("a satisfying set of honest shards rebuilds the root");
			assert_eq!(
				rebuilt.expose(),
				root().expose(),
				"holder set {mask:#x} satisfies the tree"
			);
		} else {
			assert_eq!(
				result.map(|_| ()),
				Err(RebuildError::NotSatisfied),
				"holder set {mask:#x} does not satisfy the tree, so it must not rebuild"
			);
		}
	}
}

#[test]
fn a_tree_at_the_depth_limit_rebuilds_from_its_deepest_holders() {
	let tree = Tree::new(chain(MAX_DEPTH))
		.expect("a chain at the depth limit is admitted");
	let deal_id = DealId([0x44; 32]);
	let dealt = deal_seeded(&tree, &root(), 6, &deal_id);
	let rebuilt =
		rebuild_from(&tree, &dealt, &dealt.shards, &dealt.hints, &deal_id)
			.expect("every shard of a deep tree rebuilds the root");
	assert_eq!(
		rebuilt.expose(),
		root().expose(),
		"a depth-8 tree deals and rebuilds the root"
	);

	let mut deepest_route: Vec<Path> = Vec::new();
	let mut prefix = Vec::new();
	for _ in 1..MAX_DEPTH {
		let mut sibling = prefix.clone();
		sibling.push(2);
		deepest_route.push(path(&sibling));
		prefix.push(1);
	}
	prefix.push(1);
	deepest_route.push(path(&prefix));
	let mut innermost_second = prefix.clone();
	innermost_second.pop();
	innermost_second.push(2);
	deepest_route.push(path(&innermost_second));
	let rebuilt = rebuild_from(
        &tree,
        &dealt,
        &only(&dealt, &deepest_route),
        &no_hints(),
        &deal_id,
    )
    .expect("one holder per level plus two at the bottom satisfies every 2-of-3 in the chain");
	assert_eq!(
		rebuilt.expose(),
		root().expose(),
		"a minimal set reaching depth 8 rebuilds the root without hints"
	);
	let mut short = only(&dealt, &deepest_route);
	short.remove(&path(&prefix));
	assert_eq!(
		rebuild_from(&tree, &dealt, &short, &dealt.hints, &deal_id).map(|_| ()),
		Err(RebuildError::NotSatisfied),
		"without one of the two depth-8 holders the innermost point, and so every point, fails"
	);
}

#[test]
fn a_tree_at_the_holder_limit_rebuilds_from_exactly_its_threshold() {
	for threshold in [2u8, 33, 64] {
		let tree = Tree::new(Point {
			threshold,
			children: holders(
				0,
				u16::try_from(MAX_HOLDERS).expect("MAX_HOLDERS fits u16"),
			),
		})
		.expect("a top point over the most holders is admitted");
		let deal_id = DealId([threshold; 32]);
		let dealt = deal_seeded(&tree, &root(), threshold, &deal_id);
		let last: Vec<Path> = dealt
			.shards
			.keys()
			.rev()
			.take(usize::from(threshold))
			.copied()
			.collect();
		let rebuilt = rebuild_from(
			&tree,
			&dealt,
			&only(&dealt, &last),
			&no_hints(),
			&deal_id,
		)
		.expect("any threshold-sized set of honest shards rebuilds the root");
		assert_eq!(
			rebuilt.expose(),
			root().expose(),
			"the last {threshold} of 64 holders rebuild a {threshold}-of-64 root"
		);
		assert_eq!(
			rebuild_from(
				&tree,
				&dealt,
				&only(&dealt, &last[1..]),
				&no_hints(),
				&deal_id
			)
			.map(|_| ()),
			Err(RebuildError::NotSatisfied),
			"{} holders are one short of a {threshold}-of-64 root",
			threshold - 1
		);
	}
}

#[test]
fn a_bad_shard_is_passed_over_with_hints() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let deal_id = DealId([0x55; 32]);
	let dealt = deal_seeded(&tree, &root(), 8, &deal_id);
	for bad in
		[path(&[1, 1]), path(&[1, 4]), path(&[2, 1, 2]), path(&[2, 2, 1])]
	{
		let mut shards = dealt.shards.clone();
		corrupt(&mut shards, bad);
		let rebuilt =
			rebuild_from(&tree, &dealt, &shards, &dealt.hints, &deal_id)
				.expect("one bad shard in a group with a spare is passed over");
		assert_eq!(
			rebuilt.expose(),
			root().expose(),
			"the holder hint at {bad:?} marks its shard bad and the spare takes its place"
		);
	}
}

#[test]
fn a_bad_shard_is_passed_over_without_hints() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let deal_id = DealId([0x66; 32]);
	let dealt = deal_seeded(&tree, &root(), 9, &deal_id);
	for bad in
		[path(&[1, 1]), path(&[1, 5]), path(&[2, 1, 1]), path(&[2, 2, 2])]
	{
		let mut shards = dealt.shards.clone();
		corrupt(&mut shards, bad);
		let rebuilt = rebuild_from(&tree, &dealt, &shards, &no_hints(), &deal_id)
            .expect("one bad shard in a group with a spare is passed over by trying other subsets");
		assert_eq!(
			rebuilt.expose(),
			root().expose(),
			"without hints, the root commitment rejects every subset using {bad:?}"
		);
	}
	let mut two_bad = dealt.shards.clone();
	corrupt(&mut two_bad, path(&[1, 4]));
	corrupt(&mut two_bad, path(&[1, 5]));
	let rebuilt = rebuild_from(&tree, &dealt, &two_bad, &no_hints(), &deal_id)
		.expect("Umbra's 3 of 5 still has three honest shards with two bad");
	assert_eq!(
		rebuilt.expose(),
		root().expose(),
		"two bad Umbra shards are passed over"
	);
}

#[test]
fn wrong_hints_never_block_a_rebuild() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let deal_id = DealId([0x77; 32]);
	let dealt = deal_seeded(&tree, &root(), 10, &deal_id);
	let other = deal_seeded(&tree, &root(), 11, &DealId([0x78; 32]));
	let rebuilt = rebuild_from(&tree, &dealt, &dealt.shards, &other.hints, &deal_id)
        .expect("hints from another deal match nothing, and the search runs again without them");
	assert_eq!(
		rebuilt.expose(),
		root().expose(),
		"hints never decide, so wrong hints cost a second search and nothing else"
	);
}

#[test]
fn shards_that_cannot_rebuild_the_committed_root_are_refused() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let deal_id = DealId([0x88; 32]);
	let dealt = deal_seeded(&tree, &root(), 12, &deal_id);

	let mut three_bad = dealt.shards.clone();
	for index in [1, 2, 3] {
		corrupt(&mut three_bad, path(&[1, index]));
	}
	assert_eq!(
		rebuild_from(&tree, &dealt, &three_bad, &dealt.hints, &deal_id)
			.map(|_| ()),
		Err(RebuildError::NoMatch),
		"with three of Umbra's five shards bad, no 3-subset is honest and nothing matches"
	);

	let impostor = deal_seeded(&tree, &Secret::new([0xAB; 64]), 12, &deal_id);
	assert_eq!(
		rebuild_from(
			&tree,
			&dealt,
			&impostor.shards,
			&impostor.hints,
			&deal_id
		)
		.map(|_| ()),
		Err(RebuildError::NoMatch),
		"shards of another secret rebuild that secret, whose commitment is not the expected one"
	);

	assert_eq!(
		rebuild(
			&tree,
			&dealt.shards,
			&dealt.hints,
			b"another binding",
			&deal_id,
			&dealt.root_commitment
		)
		.map(|_| ()),
		Err(RebuildError::NoMatch),
		"the root commitment binds the app binding, so another binding never matches"
	);
}

#[test]
fn a_shard_off_the_tree_is_refused() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let deal_id = DealId([0x99; 32]);
	let dealt = deal_seeded(&tree, &root(), 13, &deal_id);
	for off_tree in [path(&[2]), path(&[1, 6]), path(&[3, 1])] {
		let mut shards = dealt.shards.clone();
		shards.insert(off_tree, Shard::new([0; 64]));
		assert_eq!(
			rebuild_from(&tree, &dealt, &shards, &dealt.hints, &deal_id)
				.map(|_| ()),
			Err(RebuildError::ShardNotAtHolder { path: off_tree }),
			"a shard at {off_tree:?} belongs to another tree"
		);
	}
}

#[test]
fn a_wide_unhinted_search_gives_up_at_its_budget_and_hints_rescue_it() {
	let tree = Tree::new(Point {
		threshold: 32,
		children: holders(
			0,
			u16::try_from(MAX_HOLDERS).expect("MAX_HOLDERS fits u16"),
		),
	})
	.expect("a 32-of-64 top point is admitted");
	let deal_id = DealId([0xAA; 32]);
	let dealt = deal_seeded(&tree, &root(), 14, &deal_id);
	let mut shards = dealt.shards.clone();
	for index in 49..=64u8 {
		corrupt(&mut shards, path(&[index]));
	}
	assert_eq!(
		rebuild_from(&tree, &dealt, &shards, &no_hints(), &deal_id).map(|_| ()),
		Err(RebuildError::SearchExhausted),
		"sixteen bad shards at the end of a 32-of-64 point leave no honest subset within budget"
	);
	let rebuilt = rebuild_from(&tree, &dealt, &shards, &dealt.hints, &deal_id)
		.expect(
			"holder hints mark all sixteen bad shards, leaving 48 honest ones",
		);
	assert_eq!(
		rebuilt.expose(),
		root().expose(),
		"hints locate the bad shards the search could not"
	);
}

#[test]
fn hints_are_bound_to_their_path_deal_and_binding() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let deal_id = DealId([0xBB; 32]);
	let dealt = deal_seeded(&tree, &root(), 15, &deal_id);
	let at = path(&[1, 1]);
	let shard = dealt.shards[&at].expose();
	assert_eq!(
		dealt.hints[&at],
		point_hint(APP_BINDING, &deal_id, &at, shard),
		"a holder's hint is point_hint of its shard"
	);
	assert_eq!(
		dealt.hints[&Path::TOP],
		point_hint(APP_BINDING, &deal_id, &Path::TOP, root().expose()),
		"the top point's hint is point_hint of the root"
	);
	assert_ne!(
		point_hint(APP_BINDING, &deal_id, &path(&[1, 2]), shard),
		dealt.hints[&at],
		"the path is bound, so a shard moved to another holder fails its hint"
	);
	assert_ne!(
		point_hint(b"another binding", &deal_id, &at, shard),
		dealt.hints[&at],
		"the app binding is bound"
	);
	assert_ne!(
		point_hint(APP_BINDING, &DealId([0xBC; 32]), &at, shard),
		dealt.hints[&at],
		"the deal id is bound"
	);
	let expected_nodes = 1 + 2 + 3 + tree.holders().len();
	assert_eq!(
		dealt.hints.len(),
		expected_nodes,
		"every point and every holder has a hint"
	);
}

struct FailingRandomness;

impl RngCore for FailingRandomness {
	fn next_u32(&mut self) -> u32 {
		unreachable!("the dealer draws through try_fill_bytes only")
	}

	fn next_u64(&mut self) -> u64 {
		unreachable!("the dealer draws through try_fill_bytes only")
	}

	fn fill_bytes(&mut self, _: &mut [u8]) {
		unreachable!("the dealer draws through try_fill_bytes only")
	}

	fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
		Err(rand_core::Error::from(
			core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START)
				.expect("CUSTOM_START is nonzero"),
		))
	}
}

impl CryptoRng for FailingRandomness {}

#[test]
fn a_failing_randomness_source_fails_the_deal() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let result = deal(
		&tree,
		&root(),
		&mut FailingRandomness,
		APP_BINDING,
		&DealId([0; 32]),
	);
	assert!(
		matches!(result, Err(DealError::Randomness(_))),
		"a deal without fresh coefficients would hand out shares of a fixed polynomial"
	);
}

#[test]
fn single_holder_groups_deal_their_secret_through_unchanged() {
	let tree = Tree::new(Point {
		threshold: 2,
		children: vec![point(1, holders(0, 1)), point(1, holders(1, 1))],
	})
	.expect("two 1-of-1 groups under a 2-of-2 top are admitted");
	let deal_id = DealId([0xCC; 32]);
	let dealt = deal_seeded(&tree, &root(), 16, &deal_id);
	let rebuilt =
		rebuild_from(&tree, &dealt, &dealt.shards, &dealt.hints, &deal_id)
			.expect("both holders present satisfy the tree");
	assert_eq!(
		rebuilt.expose(),
		root().expose(),
		"a degree-0 polynomial passes its secret down"
	);
}

#[test]
fn commitments_hash_the_framed_preimages_the_design_names() {
	use sha3::{Digest, Sha3_384};

	let framed = |bytes: &[u8]| {
		[&(bytes.len() as u64).to_be_bytes()[..], bytes].concat()
	};
	let mut preimage = framed(b"root-commitment");
	preimage.extend(framed(APP_BINDING));
	preimage.extend(root().expose());
	assert_eq!(
		root_commitment(APP_BINDING, &root()).0,
		<[u8; 48]>::from(Sha3_384::digest(&preimage)),
		"the root commitment is SHA3-384 of the length-framed label and binding, then R"
	);

	let deal_id = DealId([0xDD; 32]);
	let at = path(&[2, 3, 1]);
	let secret = [0x42u8; 64];
	let mut preimage = framed(b"tree-point");
	preimage.extend(framed(APP_BINDING));
	preimage.extend(deal_id.0);
	preimage.extend([3, 2, 3, 1]);
	preimage.extend(secret);
	assert_eq!(
		point_hint(APP_BINDING, &deal_id, &at, &secret).0,
		<[u8; 48]>::from(Sha3_384::digest(&preimage)),
		"a hint is SHA3-384 of the framed label and binding, the deal id, the length-prefixed path \
         and the secret"
	);
}
