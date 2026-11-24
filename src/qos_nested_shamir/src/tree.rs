use core::fmt;
use std::collections::BTreeSet;

use sha3::{Digest, Sha3_384};

/// The deepest a holder may sit: the most child steps from the top point to a holder.
pub const MAX_DEPTH: usize = 8;

/// The most holders a tree may have.
pub const MAX_HOLDERS: usize = 64;

/// The most children one point may have, so every child index fits the Shamir x-coordinate byte.
pub const MAX_CHILDREN: usize = 255;

/// The length of a holder key digest and of a [`TreeDigest`]: SHA3-384.
pub const DIGEST_BYTES: usize = 48;

/// The version byte that opens every tree encoding.
pub const TREE_ENCODING_VERSION: u8 = 1;

const POINT_TAG: u8 = 0x01;
const HOLDER_TAG: u8 = 0x02;

/// The position of a node, as the child indices taken from the top point.
///
/// Each index is the child's Shamir x-coordinate, from 1 to [`MAX_CHILDREN`], so the first child
/// is 1, never 0. The top point's path is empty. A path holds at most [`MAX_DEPTH`] indices.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Path {
	length: u8,
	indices: [u8; MAX_DEPTH],
}

impl Path {
	/// The top point's path, which is empty.
	pub const TOP: Self = Self { length: 0, indices: [0; MAX_DEPTH] };

	/// Returns the path through `indices`, or `None` when it has more than [`MAX_DEPTH`] indices
	/// or an index is 0.
	///
	/// # Examples
	///
	/// ```
	/// use qos_nested_shamir::Path;
	///
	/// assert_eq!(Path::new(&[2, 1]).unwrap().as_slice(), &[2, 1]);
	/// assert!(Path::new(&[0]).is_none());
	/// ```
	#[must_use]
	pub fn new(indices: &[u8]) -> Option<Self> {
		let mut path = Self::TOP;
		for &index in indices {
			path = path.child(index)?;
		}
		Some(path)
	}

	/// Returns the path of this node's child at `index`, or `None` when `index` is 0 or this path
	/// already holds [`MAX_DEPTH`] indices.
	#[must_use]
	pub fn child(&self, index: u8) -> Option<Self> {
		let length = usize::from(self.length);
		if index == 0 || length == MAX_DEPTH {
			return None;
		}
		let mut child = *self;
		child.indices[length] = index;
		child.length += 1;
		Some(child)
	}

	/// Returns the child indices from the top point, the first step first.
	#[must_use]
	pub fn as_slice(&self) -> &[u8] {
		&self.indices[..usize::from(self.length)]
	}
}

impl fmt::Debug for Path {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.debug_list().entries(self.as_slice()).finish()
	}
}

/// A holder: one leaf of the tree, named by the digests of its public keys.
///
/// The digests are [`DIGEST_BYTES`] long and opaque here; the caller decides how a key is
/// digested. No digest may appear twice in one tree, across both fields of every holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Holder {
	/// The digest of the key the holder's shard is sealed to.
	pub receiving_key_digest: [u8; DIGEST_BYTES],
	/// The digest of the key the holder signs its shard with.
	pub signing_key_digest: [u8; DIGEST_BYTES],
}

/// A point: satisfied when at least `threshold` of its children are.
///
/// The fields are unchecked; [`Tree::new`] checks them against every limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Point {
	/// How many children must be satisfied, from 1 to the number of children.
	pub threshold: u8,
	/// The children in order: child `i`, from 1, has Shamir x-coordinate `i`.
	pub children: Vec<Node>,
}

/// One node of a tree: a point or a holder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
	/// An inner node with a threshold over its children.
	Point(Point),
	/// A leaf, which is satisfied when its holder takes part.
	Holder(Holder),
}

/// The SHA3-384 digest of a tree's canonical encoding ([`Tree::encode`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TreeDigest(pub [u8; DIGEST_BYTES]);

/// Why a tree, or its encoding, was refused. Each limit has its own variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeError {
	/// The top point has fewer than two children, so one group alone would rebuild the secret.
	TopTooFewChildren {
		/// The top point's number of children.
		children: usize,
	},
	/// The top point's threshold is below two, so one group alone would rebuild the secret.
	TopThresholdBelowTwo {
		/// The top point's threshold.
		threshold: u8,
	},
	/// A point has more than [`MAX_CHILDREN`] children.
	TooManyChildren {
		/// The point's path.
		path: Path,
		/// Its number of children.
		children: usize,
	},
	/// A point's threshold is zero, so it would be satisfied by no one.
	ThresholdZero {
		/// The point's path.
		path: Path,
	},
	/// A point's threshold is above its number of children, so it could never be satisfied.
	ThresholdAboveChildren {
		/// The point's path.
		path: Path,
		/// The point's threshold.
		threshold: u8,
		/// Its number of children.
		children: usize,
	},
	/// A point at depth [`MAX_DEPTH`] has children, which would sit deeper than the limit.
	TooDeep {
		/// The path of the point whose children are too deep.
		path: Path,
	},
	/// The tree has more than [`MAX_HOLDERS`] holders.
	TooManyHolders,
	/// A key digest appears twice, so one person could fill two places.
	DuplicateKey {
		/// The path of the holder where the digest appears the second time.
		path: Path,
	},
	/// The encoding ends before the tree does.
	Truncated,
	/// The encoding opens with a version other than [`TREE_ENCODING_VERSION`].
	UnsupportedVersion {
		/// The version byte found.
		version: u8,
	},
	/// A node opens with a byte that is neither the point tag nor the holder tag.
	UnknownTag {
		/// The tag byte found.
		tag: u8,
	},
	/// Bytes follow the end of the tree.
	TrailingBytes,
}

impl fmt::Display for TreeError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::TopTooFewChildren { children } => {
				write!(
					formatter,
					"the top point has {children} children, fewer than two"
				)
			}
			Self::TopThresholdBelowTwo { threshold } => {
				write!(
					formatter,
					"the top point's threshold {threshold} is below two"
				)
			}
			Self::TooManyChildren { path, children } => write!(
				formatter,
				"point {path:?} has {children} children, more than {MAX_CHILDREN}"
			),
			Self::ThresholdZero { path } => {
				write!(formatter, "point {path:?} has threshold zero")
			}
			Self::ThresholdAboveChildren { path, threshold, children } => {
				write!(
					formatter,
					"point {path:?} has threshold {threshold} above its {children} children"
				)
			}
			Self::TooDeep { path } => write!(
				formatter,
				"point {path:?} has children deeper than depth {MAX_DEPTH}"
			),
			Self::TooManyHolders => {
				write!(
					formatter,
					"the tree has more than {MAX_HOLDERS} holders"
				)
			}
			Self::DuplicateKey { path } => {
				write!(
					formatter,
					"holder {path:?} repeats a key digest already in the tree"
				)
			}
			Self::Truncated => {
				formatter.write_str("the tree encoding ends early")
			}
			Self::UnsupportedVersion { version } => {
				write!(
					formatter,
					"the tree encoding has unsupported version {version}"
				)
			}
			Self::UnknownTag { tag } => {
				write!(formatter, "the tree encoding has unknown tag {tag}")
			}
			Self::TrailingBytes => {
				formatter.write_str("bytes follow the tree encoding")
			}
		}
	}
}

impl std::error::Error for TreeError {}

/// A nested threshold tree of holders that has passed every limit.
///
/// The limits are: depth at most [`MAX_DEPTH`], at most [`MAX_HOLDERS`] holders, at most
/// [`MAX_CHILDREN`] children per point, `1 ≤ threshold ≤ children` at every point, a top point
/// with at least two children and a threshold of at least two, and no key digest twice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tree {
	top: Point,
}

impl Tree {
	/// Returns the tree under `top` once it passes every limit.
	///
	/// # Errors
	///
	/// Returns [`TreeError::TopTooFewChildren`] or [`TreeError::TopThresholdBelowTwo`] when the top
	/// point breaks its own rule, and otherwise the first other limit broken in depth-first order:
	/// [`TreeError::TooManyChildren`], [`TreeError::ThresholdZero`],
	/// [`TreeError::ThresholdAboveChildren`], [`TreeError::TooDeep`],
	/// [`TreeError::TooManyHolders`] or [`TreeError::DuplicateKey`].
	///
	/// # Examples
	///
	/// ```
	/// use qos_nested_shamir::{Holder, Node, Point, Tree};
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
	/// assert_eq!(tree.holders().len(), 3);
	/// ```
	pub fn new(top: Point) -> Result<Self, TreeError> {
		check_top(top.threshold, top.children.len())?;
		let mut walk = Walk::default();
		walk.visit_point(&top, Path::TOP)?;
		Ok(Self { top })
	}

	/// Returns the top point.
	#[must_use]
	pub fn top(&self) -> &Point {
		&self.top
	}

	/// Returns every holder with its path, depth first and in child order.
	#[must_use]
	pub fn holders(&self) -> Vec<(Path, &Holder)> {
		let mut holders = Vec::new();
		collect_holders(&self.top, Path::TOP, &mut holders);
		holders
	}

	/// Returns the holder at `path`, or `None` when no holder sits there.
	#[must_use]
	pub fn holder(&self, path: &Path) -> Option<&Holder> {
		let (last, parents) = path.as_slice().split_last()?;
		let mut point = &self.top;
		for &index in parents {
			match point.children.get(usize::from(index) - 1)? {
				Node::Point(child) => point = child,
				Node::Holder(_) => return None,
			}
		}
		match point.children.get(usize::from(*last) - 1)? {
			Node::Holder(holder) => Some(holder),
			Node::Point(_) => None,
		}
	}

	/// Returns whether the holders at `present` satisfy the tree. Paths that name no holder are
	/// ignored.
	#[must_use]
	pub fn is_satisfied_by(&self, present: &BTreeSet<Path>) -> bool {
		point_satisfied(&self.top, Path::TOP, present)
	}

	/// Returns the canonical encoding: the version byte, then the top point.
	///
	/// A point is its threshold byte, its child count byte and its children in order; every child
	/// opens with a tag byte, `0x01` for a point and `0x02` for a holder, and a holder is its
	/// receiving key digest followed by its signing key digest. The top point carries no tag. Every
	/// field has a fixed width, so a tree has exactly one encoding and [`Tree::decode`] inverts it.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let mut bytes = vec![TREE_ENCODING_VERSION];
		encode_point(&self.top, &mut bytes);
		bytes
	}

	/// Returns the tree encoded in `bytes` by [`Tree::encode`] once it passes every limit.
	///
	/// # Errors
	///
	/// Returns [`TreeError::UnsupportedVersion`], [`TreeError::UnknownTag`],
	/// [`TreeError::Truncated`] or [`TreeError::TrailingBytes`] for bytes that are not an encoding,
	/// and any error of [`Tree::new`] for a tree that breaks a limit. Depth and the holder count
	/// are refused while reading, so the work is bounded by the input length.
	pub fn decode(bytes: &[u8]) -> Result<Self, TreeError> {
		let mut reader = Reader { bytes, holders: 0 };
		let version = reader.byte()?;
		if version != TREE_ENCODING_VERSION {
			return Err(TreeError::UnsupportedVersion { version });
		}
		let top = reader.point(Path::TOP)?;
		if !reader.bytes.is_empty() {
			return Err(TreeError::TrailingBytes);
		}
		Self::new(top)
	}

	/// Returns the SHA3-384 digest of [`Tree::encode`].
	#[must_use]
	pub fn digest(&self) -> TreeDigest {
		TreeDigest(Sha3_384::digest(self.encode()).into())
	}
}

fn check_top(threshold: u8, children: usize) -> Result<(), TreeError> {
	if children < 2 {
		return Err(TreeError::TopTooFewChildren { children });
	}
	if threshold < 2 {
		return Err(TreeError::TopThresholdBelowTwo { threshold });
	}
	Ok(())
}

fn check_point(
	path: Path,
	threshold: u8,
	children: usize,
) -> Result<(), TreeError> {
	if children > MAX_CHILDREN {
		return Err(TreeError::TooManyChildren { path, children });
	}
	if threshold == 0 {
		return Err(TreeError::ThresholdZero { path });
	}
	if usize::from(threshold) > children {
		return Err(TreeError::ThresholdAboveChildren {
			path,
			threshold,
			children,
		});
	}
	Ok(())
}

fn child_path(path: Path, position: usize) -> Result<Path, TreeError> {
	let index = u8::try_from(position + 1).map_err(|_| {
		TreeError::TooManyChildren { path, children: position + 1 }
	})?;
	path.child(index).ok_or(TreeError::TooDeep { path })
}

#[derive(Default)]
struct Walk {
	holders: usize,
	keys: BTreeSet<[u8; DIGEST_BYTES]>,
}

impl Walk {
	fn visit_point(
		&mut self,
		point: &Point,
		path: Path,
	) -> Result<(), TreeError> {
		check_point(path, point.threshold, point.children.len())?;
		for (position, child) in point.children.iter().enumerate() {
			let child_path = child_path(path, position)?;
			match child {
				Node::Point(child) => self.visit_point(child, child_path)?,
				Node::Holder(holder) => {
					self.visit_holder(holder, child_path)?;
				}
			}
		}
		Ok(())
	}

	fn visit_holder(
		&mut self,
		holder: &Holder,
		path: Path,
	) -> Result<(), TreeError> {
		self.holders += 1;
		if self.holders > MAX_HOLDERS {
			return Err(TreeError::TooManyHolders);
		}
		for key in [holder.receiving_key_digest, holder.signing_key_digest] {
			if !self.keys.insert(key) {
				return Err(TreeError::DuplicateKey { path });
			}
		}
		Ok(())
	}
}

fn collect_holders<'tree>(
	point: &'tree Point,
	path: Path,
	out: &mut Vec<(Path, &'tree Holder)>,
) {
	for (position, child) in point.children.iter().enumerate() {
		let child_path = child_path(path, position)
			.expect("a validated tree has valid paths");
		match child {
			Node::Point(child) => collect_holders(child, child_path, out),
			Node::Holder(holder) => out.push((child_path, holder)),
		}
	}
}

fn point_satisfied(
	point: &Point,
	path: Path,
	present: &BTreeSet<Path>,
) -> bool {
	let satisfied = point
		.children
		.iter()
		.enumerate()
		.filter(|(position, child)| {
			let child_path = child_path(path, *position)
				.expect("a validated tree has valid paths");
			match child {
				Node::Point(child) => {
					point_satisfied(child, child_path, present)
				}
				Node::Holder(_) => present.contains(&child_path),
			}
		})
		.count();
	satisfied >= usize::from(point.threshold)
}

fn encode_point(point: &Point, bytes: &mut Vec<u8>) {
	bytes.push(point.threshold);
	bytes.push(
		u8::try_from(point.children.len())
			.expect("a validated point has at most 255 children"),
	);
	for child in &point.children {
		match child {
			Node::Point(child) => {
				bytes.push(POINT_TAG);
				encode_point(child, bytes);
			}
			Node::Holder(holder) => {
				bytes.push(HOLDER_TAG);
				bytes.extend_from_slice(&holder.receiving_key_digest);
				bytes.extend_from_slice(&holder.signing_key_digest);
			}
		}
	}
}

struct Reader<'bytes> {
	bytes: &'bytes [u8],
	holders: usize,
}

impl Reader<'_> {
	fn byte(&mut self) -> Result<u8, TreeError> {
		let (&first, rest) =
			self.bytes.split_first().ok_or(TreeError::Truncated)?;
		self.bytes = rest;
		Ok(first)
	}

	fn digest(&mut self) -> Result<[u8; DIGEST_BYTES], TreeError> {
		let (digest, rest) = self
			.bytes
			.split_first_chunk::<DIGEST_BYTES>()
			.ok_or(TreeError::Truncated)?;
		self.bytes = rest;
		Ok(*digest)
	}

	fn point(&mut self, path: Path) -> Result<Point, TreeError> {
		let threshold = self.byte()?;
		let count = usize::from(self.byte()?);
		check_point(path, threshold, count)?;
		let mut children = Vec::with_capacity(count);
		for position in 0..count {
			let child_path = child_path(path, position)?;
			let child = match self.byte()? {
				POINT_TAG => Node::Point(self.point(child_path)?),
				HOLDER_TAG => {
					self.holders += 1;
					if self.holders > MAX_HOLDERS {
						return Err(TreeError::TooManyHolders);
					}
					Node::Holder(Holder {
						receiving_key_digest: self.digest()?,
						signing_key_digest: self.digest()?,
					})
				}
				tag => return Err(TreeError::UnknownTag { tag }),
			};
			children.push(child);
		}
		Ok(Point { threshold, children })
	}
}
