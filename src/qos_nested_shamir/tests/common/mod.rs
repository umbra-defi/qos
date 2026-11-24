#![allow(dead_code)]

use qos_nested_shamir::{Holder, Node, Path, Point};

pub fn holder(number: u16) -> Node {
	let [high, low] = number.to_be_bytes();
	let mut receiving_key_digest = [0u8; 48];
	receiving_key_digest[..3].copy_from_slice(&[0x52, high, low]);
	let mut signing_key_digest = [0u8; 48];
	signing_key_digest[..3].copy_from_slice(&[0x53, high, low]);
	Node::Holder(Holder { receiving_key_digest, signing_key_digest })
}

pub fn holders(first: u16, count: u16) -> Vec<Node> {
	(first..first + count).map(holder).collect()
}

pub fn point(threshold: u8, children: Vec<Node>) -> Node {
	Node::Point(Point { threshold, children })
}

pub fn design_example() -> Point {
	Point {
		threshold: 2,
		children: vec![
			point(3, holders(1, 5)),
			point(
				2,
				vec![
					point(2, holders(10, 3)),
					point(1, holders(20, 2)),
					point(2, holders(30, 2)),
				],
			),
		],
	}
}

/// A chain of 2-of-3 points, each holding the next point and two holders, whose deepest holders
/// sit at `depth`.
pub fn chain(depth: usize) -> Point {
	let mut number = 0u16;
	let mut next = |count: u16| {
		let nodes = holders(number, count);
		number += count;
		nodes
	};
	let mut innermost = Point { threshold: 2, children: next(3) };
	for _ in 1..depth {
		let mut children = vec![Node::Point(innermost)];
		children.extend(next(2));
		innermost = Point { threshold: 2, children };
	}
	innermost
}

pub fn path(indices: &[u8]) -> Path {
	Path::new(indices).expect(
		"the test paths are within the depth limit and never use index 0",
	)
}
