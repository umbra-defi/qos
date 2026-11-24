//! A 64-byte secret dealt down a nested threshold tree of holders with Shamir over GF(2^8), and
//! rebuilt bottom up against its root commitment.
//!
//! A [`Point`] is satisfied when at least its threshold of children are, and each leaf is a
//! [`Holder`]. [`Tree::new`] and [`Tree::decode`] admit a tree only once it passes every limit,
//! each refusal a distinct [`TreeError`]; [`Tree::encode`] is its canonical encoding and
//! [`Tree::digest`] the SHA3-384 digest of that encoding.
//!
//! [`deal`] splits the secret top down with fresh randomness at every point and returns each
//! holder's [`Shard`], a [`PointHint`] per node and the [`RootCommitment`]. [`rebuild`] interpolates
//! bottom up, uses the hints to pass over bad shards, and accepts only a secret whose
//! [`root_commitment`] is the one expected. The field arithmetic is constant time with no tables.

mod commitment;
mod deal;
mod field;
#[cfg(test)]
mod proptests;
mod rebuild;
mod tree;

pub use commitment::{
	DEAL_ID_BYTES, DealId, POINT_HINT_DOMAIN, PointHint,
	ROOT_COMMITMENT_DOMAIN, RootCommitment, SECRET_BYTES, Secret, Shard,
	point_hint, root_commitment,
};
pub use deal::{Deal, DealError, deal};
pub use rebuild::{MAX_SEARCH_SHARES, RebuildError, rebuild};
pub use tree::{
	DIGEST_BYTES, Holder, MAX_CHILDREN, MAX_DEPTH, MAX_HOLDERS, Node, Path,
	Point, TREE_ENCODING_VERSION, Tree, TreeDigest, TreeError,
};
