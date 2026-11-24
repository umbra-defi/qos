use core::fmt;

use sha3::{Digest, Sha3_384};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{DIGEST_BYTES, Path};

/// The length of the root secret and of every point's secret and holder's shard.
pub const SECRET_BYTES: usize = 64;

/// The length of a [`DealId`].
pub const DEAL_ID_BYTES: usize = 32;

/// The domain label that opens every [`RootCommitment`] preimage.
pub const ROOT_COMMITMENT_DOMAIN: &[u8] = b"root-commitment";

/// The domain label that opens every [`PointHint`] preimage.
pub const POINT_HINT_DOMAIN: &[u8] = b"tree-point";

/// A 64-byte secret: the root, or a point's secret while dealing or rebuilding. Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret([u8; SECRET_BYTES]);

impl Secret {
	/// Returns the secret holding `bytes`.
	#[must_use]
	pub fn new(bytes: [u8; SECRET_BYTES]) -> Self {
		Self(bytes)
	}

	/// Returns the secret's bytes.
	#[must_use]
	pub fn expose(&self) -> &[u8; SECRET_BYTES] {
		&self.0
	}

	pub(crate) fn zeroed() -> Self {
		Self([0; SECRET_BYTES])
	}

	pub(crate) fn bytes_mut(&mut self) -> &mut [u8; SECRET_BYTES] {
		&mut self.0
	}

	pub(crate) fn ct_equals(&self, other: &Self) -> bool {
		self.0.ct_eq(&other.0).into()
	}
}

impl fmt::Debug for Secret {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("Secret(..)")
	}
}

/// One holder's shard: its leaf's 64-byte share of its parent point's secret. Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Shard([u8; SECRET_BYTES]);

impl Shard {
	/// Returns the shard holding `bytes`.
	#[must_use]
	pub fn new(bytes: [u8; SECRET_BYTES]) -> Self {
		Self(bytes)
	}

	/// Returns the shard's bytes.
	#[must_use]
	pub fn expose(&self) -> &[u8; SECRET_BYTES] {
		&self.0
	}
}

impl fmt::Debug for Shard {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("Shard(..)")
	}
}

/// The identifier of one deal, bound into every [`PointHint`] so hints from one deal never vouch
/// for shards of another. The caller draws a fresh one per deal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DealId(pub [u8; DEAL_ID_BYTES]);

/// The commitment that decides whether a rebuilt secret is the root, from [`root_commitment`].
///
/// Equality is constant time.
#[derive(Clone, Copy, Debug, Eq)]
pub struct RootCommitment(pub [u8; DIGEST_BYTES]);

impl PartialEq for RootCommitment {
	fn eq(&self, other: &Self) -> bool {
		self.0.ct_eq(&other.0).into()
	}
}

/// A hash of one node's secret in one deal, from [`point_hint`]. It locates a bad share during a
/// rebuild and never decides one.
///
/// Equality is constant time.
#[derive(Clone, Copy, Debug, Eq)]
pub struct PointHint(pub [u8; DIGEST_BYTES]);

impl PartialEq for PointHint {
	fn eq(&self, other: &Self) -> bool {
		self.0.ct_eq(&other.0).into()
	}
}

/// Returns the root commitment `H("root-commitment" ‖ app binding ‖ R)` of `secret` under
/// `app_binding`.
///
/// `H` is SHA3-384. The domain label and `app_binding` are each preceded by their length as an
/// 8-byte big-endian integer, and the 64 secret bytes follow. It names no deal, so every deal of
/// the same root under the same binding commits to the same value.
///
/// # Examples
///
/// ```
/// use qos_nested_shamir::{Secret, root_commitment};
///
/// let root = Secret::new([7; 64]);
/// assert_eq!(root_commitment(b"app", &root), root_commitment(b"app", &root));
/// assert_ne!(root_commitment(b"app", &root), root_commitment(b"other", &root));
/// ```
#[must_use]
pub fn root_commitment(app_binding: &[u8], secret: &Secret) -> RootCommitment {
	let mut hasher = Sha3_384::new();
	absorb_framed(&mut hasher, ROOT_COMMITMENT_DOMAIN);
	absorb_framed(&mut hasher, app_binding);
	hasher.update(secret.expose());
	RootCommitment(hasher.finalize().into())
}

/// Returns the hint `H("tree-point" ‖ app binding ‖ deal id ‖ path ‖ secret)` of the node at
/// `path` whose secret, or shard for a holder, is `secret`.
///
/// `H` is SHA3-384. The domain label and `app_binding` are each preceded by their length as an
/// 8-byte big-endian integer, the deal id is its 32 bytes, the path is its length in one byte
/// followed by its indices, and the 64 secret bytes follow.
///
/// # Panics
///
/// Never: a [`Path`] holds at most eight indices, so its length fits the byte it is framed in.
#[must_use]
pub fn point_hint(
	app_binding: &[u8],
	deal_id: &DealId,
	path: &Path,
	secret: &[u8; SECRET_BYTES],
) -> PointHint {
	let mut hasher = Sha3_384::new();
	absorb_framed(&mut hasher, POINT_HINT_DOMAIN);
	absorb_framed(&mut hasher, app_binding);
	hasher.update(deal_id.0);
	let indices = path.as_slice();
	hasher.update([u8::try_from(indices.len())
		.expect("a path holds at most eight indices")]);
	hasher.update(indices);
	hasher.update(secret);
	PointHint(hasher.finalize().into())
}

fn absorb_framed(hasher: &mut Sha3_384, bytes: &[u8]) {
	hasher.update((bytes.len() as u64).to_be_bytes());
	hasher.update(bytes);
}
