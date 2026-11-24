//! Tree construction, limits and encoding.

mod common;

use std::collections::BTreeSet;

use common::{chain, design_example, holder, holders, path, point};
use qos_nested_shamir::{
	Holder, MAX_CHILDREN, MAX_DEPTH, MAX_HOLDERS, Node, Path, Point,
	TREE_ENCODING_VERSION, Tree, TreeError,
};
use sha3::{Digest, Sha3_384};

#[test]
fn the_design_example_is_admitted_with_its_holders_in_depth_first_order() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let paths: Vec<Vec<u8>> = tree
		.holders()
		.iter()
		.map(|(path, _)| path.as_slice().to_vec())
		.collect();
	assert_eq!(
		paths.len(),
		12,
		"the example has five Umbra and seven external holders"
	);
	assert_eq!(
		paths[0],
		vec![1, 1],
		"the first holder is the first child of the first group"
	);
	assert_eq!(
		paths[11],
		vec![2, 3, 2],
		"the last holder is Org C's second holder"
	);
	assert_eq!(
		tree.holder(&path(&[2, 2, 1])),
		Some(&match holder(20) {
			Node::Holder(holder) => holder,
			Node::Point(_) => unreachable!("holder() builds holders"),
		}),
		"holder lookup by path finds Org B's first holder"
	);
	assert_eq!(
		tree.holder(&path(&[2])),
		None,
		"a path that names a point names no holder"
	);
	assert_eq!(
		tree.holder(&path(&[3])),
		None,
		"a path past the last child names no holder"
	);
}

#[test]
fn satisfaction_follows_the_thresholds() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let set = |paths: &[&[u8]]| {
		paths.iter().map(|indices| path(indices)).collect::<BTreeSet<_>>()
	};
	let umbra = [&[1, 1][..], &[1, 3], &[1, 5]];
	let org_a = [&[2, 1, 1][..], &[2, 1, 3]];
	let org_b = [&[2, 2, 2][..]];
	let satisfying: Vec<&[u8]> =
		umbra.iter().chain(&org_a).chain(&org_b).copied().collect();
	assert!(
		tree.is_satisfied_by(&set(&satisfying)),
		"three Umbra holders with Org A and Org B satisfy both groups"
	);
	let without_org_b: Vec<&[u8]> =
		umbra.iter().chain(&org_a).copied().collect();
	assert!(
		!tree.is_satisfied_by(&set(&without_org_b)),
		"one external organisation is short of the externals' 2 of 3"
	);
	let two_umbra: Vec<&[u8]> =
		umbra[..2].iter().chain(&org_a).chain(&org_b).copied().collect();
	assert!(
		!tree.is_satisfied_by(&set(&two_umbra)),
		"two Umbra holders are short of Umbra's 3 of 5"
	);
}

#[test]
fn trees_at_every_limit_are_admitted() {
	let wide = Tree::new(Point {
		threshold: 64,
		children: holders(
			0,
			u16::try_from(MAX_HOLDERS).expect("MAX_HOLDERS fits u16"),
		),
	});
	assert!(
		wide.is_ok(),
		"a top point with exactly the most holders is within the limits"
	);
	let deep = Tree::new(chain(MAX_DEPTH))
		.expect("a chain whose holders sit at the depth limit is admitted");
	let deepest =
		deep.holders().iter().map(|(path, _)| path.as_slice().len()).max();
	assert_eq!(
		deepest,
		Some(MAX_DEPTH),
		"the chain's deepest holders sit exactly at the limit"
	);
}

#[test]
fn a_top_point_may_have_one_child() {
	assert!(
		Tree::new(Point {
			threshold: 1,
			children: vec![point(2, holders(0, 3))]
		})
		.is_ok(),
		"how many groups the top needs is the operator's policy, not the tree's"
	);
}

#[test]
fn a_top_point_may_have_threshold_one() {
	assert!(
		Tree::new(Point {
			threshold: 1,
			children: vec![point(2, holders(0, 3)), point(1, holders(3, 2))],
		})
		.is_ok(),
		"either group alone may rebuild the secret when the operator chooses so"
	);
}

#[test]
fn a_point_with_more_than_255_children_is_refused() {
	let children = (0..=u16::try_from(MAX_CHILDREN)
		.expect("MAX_CHILDREN fits u16"))
		.map(holder)
		.collect::<Vec<_>>();
	assert_eq!(
		Tree::new(Point {
			threshold: 2,
			children: vec![point(1, children), holder(1000)],
		}),
		Err(TreeError::TooManyChildren {
			path: path(&[1]),
			children: MAX_CHILDREN + 1
		}),
		"a 256th child has no Shamir x-coordinate in GF(2^8), and the child count is checked \
         before the holders are counted"
	);
}

#[test]
fn a_point_with_threshold_zero_is_refused() {
	assert_eq!(
		Tree::new(Point {
			threshold: 2,
			children: vec![point(0, holders(0, 2)), holder(10)],
		}),
		Err(TreeError::ThresholdZero { path: path(&[1]) }),
		"a 0-of-m point would be satisfied by no holder at all"
	);
}

#[test]
fn a_point_with_threshold_above_its_children_is_refused() {
	assert_eq!(
		Tree::new(Point {
			threshold: 2,
			children: vec![holder(10), point(3, holders(0, 2))],
		}),
		Err(TreeError::ThresholdAboveChildren {
			path: path(&[2]),
			threshold: 3,
			children: 2
		}),
		"a 3-of-2 point can never be satisfied"
	);
	assert_eq!(
		Tree::new(Point { threshold: 3, children: holders(0, 2) }),
		Err(TreeError::ThresholdAboveChildren {
			path: Path::TOP,
			threshold: 3,
			children: 2
		}),
		"the top point is held to the same threshold bound"
	);
	assert_eq!(
		Tree::new(Point {
			threshold: 2,
			children: vec![holder(10), point(1, Vec::new())],
		}),
		Err(TreeError::ThresholdAboveChildren {
			path: path(&[2]),
			threshold: 1,
			children: 0
		}),
		"a point with no children can never be satisfied"
	);
}

#[test]
fn a_tree_deeper_than_eight_is_refused() {
	let too_deep = chain(MAX_DEPTH + 1);
	assert_eq!(
		Tree::new(too_deep),
		Err(TreeError::TooDeep { path: path(&[1; MAX_DEPTH]) }),
		"the point at depth eight may not have children, which would sit at depth nine"
	);
}

#[test]
fn a_tree_with_more_than_64_holders_is_refused() {
	assert_eq!(
		Tree::new(Point {
			threshold: 2,
			children: vec![
				point(1, holders(0, 32)),
				point(1, holders(100, 33))
			],
		}),
		Err(TreeError::TooManyHolders),
		"65 holders is over the limit"
	);
}

#[test]
fn a_repeated_key_digest_is_refused() {
	assert_eq!(
		Tree::new(Point {
			threshold: 2,
			children: vec![
				point(1, holders(0, 3)),
				point(1, vec![holder(5), holder(2)])
			],
		}),
		Err(TreeError::DuplicateKey { path: path(&[2, 2]) }),
		"the same holder in two branches lets one person fill both"
	);
	let shared_signing_key = |receiving: u8| {
		Node::Holder(Holder {
			receiving_key_digest: [receiving; 48],
			signing_key_digest: [0xEE; 48],
		})
	};
	assert_eq!(
		Tree::new(Point {
			threshold: 2,
			children: vec![shared_signing_key(1), shared_signing_key(2)],
		}),
		Err(TreeError::DuplicateKey { path: path(&[2]) }),
		"two holders sharing one signing key are one person, whatever their receiving keys"
	);
	assert_eq!(
		Tree::new(Point {
			threshold: 2,
			children: vec![
				holder(1),
				Node::Holder(Holder {
					receiving_key_digest: [0x77; 48],
					signing_key_digest: [0x77; 48],
				}),
			],
		}),
		Err(TreeError::DuplicateKey { path: path(&[2]) }),
		"a holder whose two digests are equal repeats a key"
	);
}

#[test]
fn the_encoding_round_trips_and_is_canonical() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let encoding = tree.encode();
	assert_eq!(
		encoding[0], TREE_ENCODING_VERSION,
		"the encoding opens with its version byte"
	);
	assert_eq!(
		&encoding[1..3],
		&[2, 2],
		"the top point has no tag: threshold then child count"
	);
	assert_eq!(encoding[3], 0x01, "the top point's first child is a point");
	assert_eq!(
		encoding.len(),
		1 + 2 + 5 * (1 + 2) + 12 * (1 + 96),
		"one version byte, the top point's header, five tagged points and 12 tagged holders"
	);
	assert_eq!(
		Tree::decode(&encoding),
		Ok(tree.clone()),
		"decoding an encoding gives the same tree back"
	);
	assert_eq!(
		tree.digest().0,
		<[u8; 48]>::from(Sha3_384::digest(&encoding)),
		"the tree digest is SHA3-384 over the encoding"
	);
	let reordered = Tree::new(Point {
		threshold: 2,
		children: design_example().children.into_iter().rev().collect(),
	})
	.expect("the example with its groups swapped breaks no limit");
	assert_ne!(
		reordered.digest(),
		tree.digest(),
		"child order fixes each child's x-coordinate, so it is part of the digest"
	);
}

#[test]
fn the_encoding_is_a_fixed_vector() {
	let tree = Tree::new(Point {
		threshold: 2,
		children: vec![holder(1), point(1, vec![holder(2)])],
	})
	.expect("a 2-of-2 over a holder and a 1-of-1 group breaks no limit");
	let mut expected = vec![0x01, 0x02, 0x02, 0x02];
	expected.extend([0x52, 0x00, 0x01]);
	expected.extend([0u8; 45]);
	expected.extend([0x53, 0x00, 0x01]);
	expected.extend([0u8; 45]);
	expected.extend([0x01, 0x01, 0x01, 0x02]);
	expected.extend([0x52, 0x00, 0x02]);
	expected.extend([0u8; 45]);
	expected.extend([0x53, 0x00, 0x02]);
	expected.extend([0u8; 45]);
	assert_eq!(tree.encode(), expected, "the encoding's byte layout is fixed");
	assert_eq!(
		hex::encode(tree.digest().0),
		hex::encode(Sha3_384::digest(&expected)),
		"the digest of the fixed vector is SHA3-384 of its bytes"
	);
}

#[test]
fn malformed_encodings_are_refused() {
	let tree = Tree::new(design_example())
		.expect("the design's example tree breaks no limit");
	let encoding = tree.encode();

	let mut wrong_version = encoding.clone();
	wrong_version[0] = 2;
	assert_eq!(
		Tree::decode(&wrong_version),
		Err(TreeError::UnsupportedVersion { version: 2 }),
		"an encoding from another version is not read as this one"
	);

	for length in 0..encoding.len() {
		assert_eq!(
			Tree::decode(&encoding[..length]),
			Err(TreeError::Truncated),
			"an encoding cut at byte {length} is incomplete"
		);
	}

	let mut trailing = encoding.clone();
	trailing.push(0);
	assert_eq!(
		Tree::decode(&trailing),
		Err(TreeError::TrailingBytes),
		"bytes after the tree would give one tree two encodings"
	);

	let mut unknown_tag = encoding.clone();
	unknown_tag[3] = 0x03;
	assert_eq!(
		Tree::decode(&unknown_tag),
		Err(TreeError::UnknownTag { tag: 0x03 }),
		"a node tag other than point or holder is not guessed at"
	);
}

#[test]
fn decoding_applies_every_limit() {
	let mut top_threshold_zero = Tree::new(design_example())
		.expect("the design's example tree breaks no limit")
		.encode();
	top_threshold_zero[1] = 0;
	assert!(
		matches!(
			Tree::decode(&top_threshold_zero),
			Err(TreeError::ThresholdZero { .. })
		),
		"a decoded tree is held to every limit, the top point's included"
	);

	let mut deep = vec![TREE_ENCODING_VERSION, 1, 1];
	for _ in 0..=MAX_DEPTH {
		deep.extend([0x01, 1, 1]);
	}
	assert_eq!(
		Tree::decode(&deep),
		Err(TreeError::TooDeep { path: path(&[1; MAX_DEPTH]) }),
		"depth is refused while reading, before the tree is complete"
	);

	let mut many = vec![TREE_ENCODING_VERSION, 2, 65];
	for number in 0..65u8 {
		many.push(0x02);
		many.extend([number; 48]);
		many.extend([number | 0x80; 48]);
	}
	assert_eq!(
		Tree::decode(&many),
		Err(TreeError::TooManyHolders),
		"the holder count is refused while reading"
	);

	let mut repeated = vec![TREE_ENCODING_VERSION, 2, 2];
	for _ in 0..2 {
		repeated.push(0x02);
		repeated.extend([7u8; 48]);
		repeated.extend([8u8; 48]);
	}
	assert_eq!(
		Tree::decode(&repeated),
		Err(TreeError::DuplicateKey { path: path(&[2]) }),
		"a decoded tree is held to the distinct-key rule"
	);
}

#[test]
fn paths_refuse_index_zero_and_depth_past_the_limit() {
	assert!(
		Path::new(&[0]).is_none(),
		"x = 0 is the secret itself, never a child"
	);
	assert!(
		Path::new(&[1; MAX_DEPTH + 1]).is_none(),
		"a path longer than the depth limit names no node"
	);
	assert_eq!(
		Path::new(&[3, 255]).map(|path| path.as_slice().to_vec()),
		Some(vec![3, 255]),
		"a path keeps its indices in order"
	);
	assert_eq!(
		Path::TOP.as_slice(),
		&[] as &[u8],
		"the top point's path is empty"
	);
}
