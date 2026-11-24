//! The quorum key envelope: the quorum key's master seed sealed under a fresh 64-byte envelope key,
//! which is dealt down the share set's holder tree with [`qos_nested_shamir`]. The seed itself is
//! never split, so a reshare can seal the same seed under a new key dealt over a new tree, and the
//! quorum key outlives any one set of holders.
//!
//! # Encoding
//!
//! Fields follow one another with no padding; integers are little-endian. The version
//! [`ENVELOPE_VERSION`], the deal id (32 bytes), the holder tree's digest (48), the root commitment
//! (48), the AES-256-GCM nonce (12), the ciphertext's length (4) and the ciphertext, the hint count
//! (4), then each hint as its path (the depth as one byte, then the indices) and its 48 bytes,
//! ascending by path.
//!
//! # Sealing
//!
//! The AES-256-GCM key is HKDF-SHA512 of the envelope key under [`ENVELOPE_KEY_INFO`]. The
//! associated data is [`ENVELOPE_AAD_DOMAIN`], the quorum public key, the tree digest, the deal id
//! and the root commitment, so an envelope opens only for the quorum key, tree and deal it was
//! sealed for. The deal's app binding is [`envelope_binding`] of the quorum public key.

use std::collections::BTreeMap;

use aes_gcm::{
	Aes256Gcm, KeyInit, Nonce,
	aead::{Aead, Payload},
};
use hkdf::Hkdf;
use qos_nested_shamir::{
	DEAL_ID_BYTES, DIGEST_BYTES, DealId, Path, PointHint, RootCommitment,
	SECRET_BYTES, Secret, Shard, Tree, deal, rebuild,
};
use rand_core06::{OsRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

use crate::protocol::ProtocolError;

/// The version byte that opens an encoded [`QuorumKeyEnvelope`].
pub const ENVELOPE_VERSION: u8 = 1;

/// The HKDF info the AES-256-GCM key is derived under.
pub const ENVELOPE_KEY_INFO: &[u8] = b"qos_quorum_key_envelope_key_v1";

/// The domain label that opens the associated data.
pub const ENVELOPE_AAD_DOMAIN: &[u8] = b"qos_quorum_key_envelope_v1";

/// The domain label of [`envelope_binding`].
pub const ENVELOPE_BINDING_DOMAIN: &[u8] =
	b"qos_quorum_key_envelope_binding_v1";

/// The domain label of [`QuorumKeyEnvelope::digest`].
pub const ENVELOPE_DIGEST_DOMAIN: &[u8] = b"qos_quorum_key_envelope_digest_v1";

const NONCE_BYTES: usize = 12;
const SEED_BYTES: usize = qos_hybrid::MASTER_SEED_LEN;
const MAX_HINTS: usize = 2 * qos_nested_shamir::MAX_HOLDERS * 8 + 1;

/// The quorum key's master seed sealed under a dealt envelope key, with what an enclave needs to
/// rebuild that key: the deal's id, tree digest, root commitment and every node's hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumKeyEnvelope {
	/// Names the deal the hints and shards belong to.
	pub deal_id: DealId,
	/// The digest of the holder tree the envelope key was dealt over.
	pub tree_digest: [u8; DIGEST_BYTES],
	/// The commitment a rebuilt envelope key must match.
	pub root_commitment: RootCommitment,
	/// The AES-256-GCM nonce.
	pub nonce: [u8; NONCE_BYTES],
	/// The sealed master seed and its tag.
	pub ciphertext: Vec<u8>,
	/// Every node's hint, keyed by path.
	pub hints: BTreeMap<Path, PointHint>,
}

/// The deal's app binding for a quorum key: SHA-512 over [`ENVELOPE_BINDING_DOMAIN`] and the
/// quorum public key, the same for every deal of that key.
#[must_use]
pub fn envelope_binding(quorum_public_key: &[u8]) -> [u8; 64] {
	let mut hasher = Sha512::new();
	hasher.update(ENVELOPE_BINDING_DOMAIN);
	hasher.update(quorum_public_key);
	hasher.finalize().into()
}

/// Seals `master_seed` under a fresh envelope key dealt over `tree`, returning the envelope and
/// each holder's shard by path.
///
/// # Errors
///
/// [`ProtocolError::QuorumKeyEnvelope`] when the randomness source or the AEAD fails.
pub fn seal_quorum_key(
	master_seed: &[u8; SEED_BYTES],
	quorum_public_key: &[u8],
	tree: &Tree,
) -> Result<(QuorumKeyEnvelope, BTreeMap<Path, Shard>), ProtocolError> {
	let mut envelope_key = Zeroizing::new([0u8; SECRET_BYTES]);
	let mut deal_id = [0u8; DEAL_ID_BYTES];
	let mut nonce = [0u8; NONCE_BYTES];
	OsRng.fill_bytes(envelope_key.as_mut());
	OsRng.fill_bytes(&mut deal_id);
	OsRng.fill_bytes(&mut nonce);
	let envelope_key = Secret::new(*envelope_key);
	let deal_id = DealId(deal_id);
	let binding = envelope_binding(quorum_public_key);

	let dealt = deal(tree, &envelope_key, &mut OsRng, &binding, &deal_id)
		.map_err(|e| envelope_error(format!("deal failed: {e:?}")))?;

	let mut envelope = QuorumKeyEnvelope {
		deal_id,
		tree_digest: tree.digest().0,
		root_commitment: dealt.root_commitment,
		nonce,
		ciphertext: Vec::new(),
		hints: dealt.hints,
	};
	let aad = associated_data(quorum_public_key, &envelope);
	envelope.ciphertext = cipher(&envelope_key)?
		.encrypt(
			Nonce::from_slice(&nonce),
			Payload { msg: master_seed, aad: &aad },
		)
		.map_err(|_| envelope_error("sealing the master seed failed"))?;
	Ok((envelope, dealt.shards))
}

/// Rebuilds the envelope key from `shards` and opens the master seed.
///
/// # Errors
///
/// [`ProtocolError::QuorumKeyEnvelope`] when the envelope was dealt over another tree, the shards
/// do not rebuild the committed key, or the ciphertext does not open for this quorum key.
pub fn open_quorum_key(
	envelope: &QuorumKeyEnvelope,
	quorum_public_key: &[u8],
	tree: &Tree,
	shards: &BTreeMap<Path, Shard>,
) -> Result<Zeroizing<[u8; SEED_BYTES]>, ProtocolError> {
	if tree.digest().0 != envelope.tree_digest {
		return Err(envelope_error(
			"the envelope was dealt over another holder tree",
		));
	}
	let envelope_key = rebuild(
		tree,
		shards,
		&envelope.hints,
		&envelope_binding(quorum_public_key),
		&envelope.deal_id,
		&envelope.root_commitment,
	)
	.map_err(|e| envelope_error(format!("rebuild failed: {e:?}")))?;
	let aad = associated_data(quorum_public_key, envelope);
	let seed = Zeroizing::new(
		cipher(&envelope_key)?
			.decrypt(
				Nonce::from_slice(&envelope.nonce),
				Payload { msg: &envelope.ciphertext, aad: &aad },
			)
			.map_err(|_| {
				envelope_error("the envelope does not open for this quorum key")
			})?,
	);
	let seed: [u8; SEED_BYTES] = seed[..].try_into().map_err(|_| {
		envelope_error("the sealed master seed has the wrong length")
	})?;
	Ok(Zeroizing::new(seed))
}

impl QuorumKeyEnvelope {
	/// The envelope's canonical encoding.
	///
	/// # Panics
	///
	/// Never: a path holds at most eight indices, and every field is far below 4 GiB.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let mut out = vec![ENVELOPE_VERSION];
		out.extend_from_slice(&self.deal_id.0);
		out.extend_from_slice(&self.tree_digest);
		out.extend_from_slice(&self.root_commitment.0);
		out.extend_from_slice(&self.nonce);
		out.extend_from_slice(&length(self.ciphertext.len()));
		out.extend_from_slice(&self.ciphertext);
		out.extend_from_slice(&length(self.hints.len()));
		for (path, hint) in &self.hints {
			let indices = path.as_slice();
			out.push(
				u8::try_from(indices.len())
					.expect("a path holds at most eight indices"),
			);
			out.extend_from_slice(indices);
			out.extend_from_slice(&hint.0);
		}
		out
	}

	/// Decodes an envelope, refusing anything but one canonical encoding.
	///
	/// # Errors
	///
	/// [`ProtocolError::QuorumKeyEnvelope`] naming what is malformed.
	pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
		let mut reader = Reader { bytes };
		if reader.take(1)? != [ENVELOPE_VERSION] {
			return Err(envelope_error("unknown envelope version"));
		}
		let deal_id = DealId(reader.array()?);
		let tree_digest = reader.array()?;
		let root_commitment = RootCommitment(reader.array()?);
		let nonce = reader.array()?;
		let ciphertext_len = reader.length()?;
		if ciphertext_len != SEED_BYTES + 16 {
			return Err(envelope_error("the ciphertext is not a sealed seed"));
		}
		let ciphertext = reader.take(ciphertext_len)?.to_vec();
		let hint_count = reader.length()?;
		if hint_count > MAX_HINTS {
			return Err(envelope_error("too many hints"));
		}
		let mut hints = BTreeMap::new();
		let mut previous: Option<Path> = None;
		for _ in 0..hint_count {
			let depth = usize::from(reader.take(1)?[0]);
			let path = Path::new(reader.take(depth)?)
				.ok_or_else(|| envelope_error("a hint's path is malformed"))?;
			if previous.is_some_and(|previous| previous >= path) {
				return Err(envelope_error("hints are not ascending by path"));
			}
			previous = Some(path);
			hints.insert(path, PointHint(reader.array()?));
		}
		if !reader.bytes.is_empty() {
			return Err(envelope_error("trailing bytes after the envelope"));
		}
		Ok(Self {
			deal_id,
			tree_digest,
			root_commitment,
			nonce,
			ciphertext,
			hints,
		})
	}

	/// SHA-512 over [`ENVELOPE_DIGEST_DOMAIN`] and the encoding: what a manifest names the
	/// envelope by.
	#[must_use]
	pub fn digest(&self) -> [u8; 64] {
		let mut hasher = Sha512::new();
		hasher.update(ENVELOPE_DIGEST_DOMAIN);
		hasher.update(self.encode());
		hasher.finalize().into()
	}
}

/// Length of [`encode_shard`]'s output.
pub const ENCODED_SHARD_BYTES: usize = DEAL_ID_BYTES + SECRET_BYTES;

/// A holder's shard as genesis seals it and a holder posts it: its deal id, then its 64 bytes.
#[must_use]
pub fn encode_shard(deal_id: &DealId, shard: &Shard) -> Zeroizing<Vec<u8>> {
	let mut out = Zeroizing::new(Vec::with_capacity(ENCODED_SHARD_BYTES));
	out.extend_from_slice(&deal_id.0);
	out.extend_from_slice(shard.expose());
	out
}

/// Splits [`encode_shard`]'s output.
///
/// # Errors
///
/// [`ProtocolError::ShareNotForMember`] unless `bytes` is [`ENCODED_SHARD_BYTES`] long.
///
/// # Panics
///
/// Never: the length is checked before the split.
pub fn decode_shard(bytes: &[u8]) -> Result<(DealId, Shard), ProtocolError> {
	if bytes.len() != ENCODED_SHARD_BYTES {
		return Err(ProtocolError::ShareNotForMember);
	}
	let (deal_id, shard) = bytes.split_at(DEAL_ID_BYTES);
	Ok((
		DealId(deal_id.try_into().expect("split at the deal id's length")),
		Shard::new(shard.try_into().expect("the rest is one shard")),
	))
}

fn associated_data(
	quorum_public_key: &[u8],
	envelope: &QuorumKeyEnvelope,
) -> Vec<u8> {
	let mut aad = ENVELOPE_AAD_DOMAIN.to_vec();
	aad.extend_from_slice(&length(quorum_public_key.len()));
	aad.extend_from_slice(quorum_public_key);
	aad.extend_from_slice(&envelope.tree_digest);
	aad.extend_from_slice(&envelope.deal_id.0);
	aad.extend_from_slice(&envelope.root_commitment.0);
	aad
}

fn cipher(envelope_key: &Secret) -> Result<Aes256Gcm, ProtocolError> {
	let mut key = Zeroizing::new([0u8; 32]);
	Hkdf::<Sha512>::new(None, envelope_key.expose())
		.expand(ENVELOPE_KEY_INFO, key.as_mut())
		.map_err(|_| {
			envelope_error("deriving the envelope cipher key failed")
		})?;
	Aes256Gcm::new_from_slice(key.as_ref())
		.map_err(|_| envelope_error("the envelope cipher key was refused"))
}

fn length(len: usize) -> [u8; 4] {
	u32::try_from(len)
		.expect("envelope fields are far below 4 GiB")
		.to_le_bytes()
}

fn envelope_error(reason: impl Into<String>) -> ProtocolError {
	ProtocolError::QuorumKeyEnvelope(reason.into())
}

struct Reader<'a> {
	bytes: &'a [u8],
}

impl<'a> Reader<'a> {
	fn take(&mut self, count: usize) -> Result<&'a [u8], ProtocolError> {
		if self.bytes.len() < count {
			return Err(envelope_error("the envelope is truncated"));
		}
		let (head, tail) = self.bytes.split_at(count);
		self.bytes = tail;
		Ok(head)
	}

	fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
		Ok(self.take(N)?.try_into().expect("take returned N bytes"))
	}

	fn length(&mut self) -> Result<usize, ProtocolError> {
		let bytes: [u8; 4] = self.array()?;
		usize::try_from(u32::from_le_bytes(bytes))
			.map_err(|_| envelope_error("a length does not fit"))
	}
}

#[cfg(test)]
mod test {
	use qos_hybrid::HybridPair;
	use qos_nested_shamir::{Holder, Node, Point};

	use super::*;

	fn holder(seed: u8) -> Node {
		Node::Holder(Holder {
			receiving_key_digest: [seed; DIGEST_BYTES],
			signing_key_digest: [seed.wrapping_add(100); DIGEST_BYTES],
		})
	}

	/// Either of two groups: 2 of 3, or 1 of 2.
	fn tree() -> Tree {
		Tree::new(Point {
			threshold: 1,
			children: vec![
				Node::Point(Point {
					threshold: 2,
					children: vec![holder(1), holder(2), holder(3)],
				}),
				Node::Point(Point {
					threshold: 1,
					children: vec![holder(4), holder(5)],
				}),
			],
		})
		.unwrap()
	}

	fn sealed() -> (HybridPair, QuorumKeyEnvelope, BTreeMap<Path, Shard>) {
		let quorum = HybridPair::generate().unwrap();
		let seed = quorum.to_master_seed();
		let (envelope, shards) =
			seal_quorum_key(seed, &quorum.public_key().to_bytes(), &tree())
				.unwrap();
		(quorum, envelope, shards)
	}

	fn only(
		shards: &BTreeMap<Path, Shard>,
		paths: &[&[u8]],
	) -> BTreeMap<Path, Shard> {
		paths
			.iter()
			.map(|indices| {
				let path = Path::new(indices).unwrap();
				(path, shards[&path].clone())
			})
			.collect()
	}

	#[test]
	fn either_group_opens_the_seed_and_neither_part_does() {
		let (quorum, envelope, shards) = sealed();
		let public = quorum.public_key().to_bytes();
		for paths in [&[&[1u8, 1][..], &[1, 3]][..], &[&[2, 2]]] {
			let seed = open_quorum_key(
				&envelope,
				&public,
				&tree(),
				&only(&shards, paths),
			)
			.unwrap();
			assert_eq!(seed[..], quorum.to_master_seed()[..]);
		}
		assert!(
			open_quorum_key(
				&envelope,
				&public,
				&tree(),
				&only(&shards, &[&[1, 1]])
			)
			.is_err(),
			"one of a 2-of-3 group must not open the seed"
		);
	}

	#[test]
	fn the_envelope_opens_only_for_its_quorum_key() {
		let (_, envelope, shards) = sealed();
		let other = HybridPair::generate().unwrap().public_key().to_bytes();
		assert!(open_quorum_key(&envelope, &other, &tree(), &shards).is_err());
	}

	#[test]
	fn the_envelope_round_trips_and_its_digest_covers_every_field() {
		let (_, envelope, _) = sealed();
		let encoded = envelope.encode();
		assert_eq!(QuorumKeyEnvelope::decode(&encoded).unwrap(), envelope);
		let mut altered = encoded.clone();
		*altered.last_mut().unwrap() ^= 1;
		let altered = QuorumKeyEnvelope::decode(&altered).unwrap();
		assert_ne!(altered.digest(), envelope.digest());
		let mut trailing = encoded;
		trailing.push(0);
		assert!(QuorumKeyEnvelope::decode(&trailing).is_err());
	}

	#[test]
	fn a_reseal_of_the_same_seed_shares_nothing_with_the_first() {
		let (quorum, first, first_shards) = sealed();
		let public = quorum.public_key().to_bytes();
		let (second, second_shards) =
			seal_quorum_key(quorum.to_master_seed(), &public, &tree()).unwrap();
		assert_ne!(first.deal_id, second.deal_id);
		assert_ne!(first.root_commitment, second.root_commitment);
		assert!(
			open_quorum_key(&second, &public, &tree(), &first_shards).is_err(),
			"old shards must not open a resealed envelope"
		);
		assert!(
			open_quorum_key(&second, &public, &tree(), &second_shards).is_ok()
		);
	}
}
