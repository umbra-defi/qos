//! Hybrid ML-DSA-87 + SLH-DSA-SHA2-256s + Ed25519 signing and verification.
//!
//! A signature is
//! `ml_dsa_87_signature||slh_dsa_sha2_256s_signature||ed25519_signature`, and
//! verifies only if all three parts verify, so a forger has to break all
//! three schemes: two post-quantum schemes on unrelated assumptions (module
//! lattices and hash functions alone) and one classical scheme. Every part is
//! bound to [`SIGNING_DOMAIN`]: it is the ML-DSA-87 and SLH-DSA context string
//! and prefixes the message Ed25519 signs, so no part verifies as a plain
//! signature of its scheme.
//!
//! ML-DSA-87 and SLH-DSA signatures are hedged: each one mixes fresh random
//! bytes into its signing randomness (the FIPS 204 and FIPS 205 hedged
//! variants), so two signatures over the same message differ while both
//! verify. Ed25519 verification is strict (`verify_strict`), refusing
//! small-order keys and non-canonical encodings.

use ed25519_dalek::{
	Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey,
};
use fips204::{
	ml_dsa_87,
	traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _},
};
use fips205::{
	slh_dsa_sha2_256s,
	traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _},
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
	DERIVED_SECRET_LEN, ED25519_PUBLIC_LEN, ED25519_SIGNATURE_LEN, HybridError,
	ML_DSA_PUBLIC_LEN, ML_DSA_SIGNATURE_LEN, SIGN_PUBLIC_LEN, SIGNATURE_LEN,
	SLH_DSA_PUBLIC_LEN, SLH_DSA_SIGNATURE_LEN, bytes_os_rng,
};

/// Domain every signature part is bound to.
pub const SIGNING_DOMAIN: &[u8] =
	b"qos_hybrid_ml_dsa_87_slh_dsa_sha2_256s_ed25519_v1";

/// The three FIPS 205 key generation seeds of an SLH-DSA-SHA2-256s key.
pub struct SlhDsaSeeds<'a> {
	/// `SK.seed`, the secret seed of every WOTS+ and FORS key.
	pub secret_seed: &'a Zeroizing<[u8; DERIVED_SECRET_LEN]>,
	/// `SK.prf`, the secret key of the message randomizer.
	pub secret_prf: &'a Zeroizing<[u8; DERIVED_SECRET_LEN]>,
	/// `PK.seed`, the public seed that tweaks every hash call.
	pub public_seed: &'a Zeroizing<[u8; DERIVED_SECRET_LEN]>,
}

/// ML-DSA-87 + SLH-DSA-SHA2-256s + Ed25519 signing key pair.
#[derive(ZeroizeOnDrop)]
pub struct HybridSignPair {
	ml_dsa: ml_dsa_87::PrivateKey,
	slh_dsa: slh_dsa_sha2_256s::PrivateKey,
	ed25519: SigningKey,
	#[zeroize(skip)]
	public: HybridSignPublic,
}

impl HybridSignPair {
	/// Build the pair from the ML-DSA-87 `xi` seed, the SLH-DSA-SHA2-256s
	/// seeds and the Ed25519 seed.
	#[must_use]
	pub fn from_seeds(
		ml_dsa_xi: &Zeroizing<[u8; DERIVED_SECRET_LEN]>,
		slh_dsa: &SlhDsaSeeds<'_>,
		ed25519_seed: &Zeroizing<[u8; DERIVED_SECRET_LEN]>,
	) -> Self {
		let (ml_dsa_public, ml_dsa) =
			ml_dsa_87::KG::keygen_from_seed(ml_dsa_xi);
		let (slh_dsa_public, slh_dsa_private) =
			slh_dsa_sha2_256s::KG::keygen_from_seed(
				slh_dsa.secret_seed,
				slh_dsa.secret_prf,
				slh_dsa.public_seed,
			);
		let ed25519 = SigningKey::from_bytes(ed25519_seed);

		Self {
			ml_dsa,
			slh_dsa: slh_dsa_private,
			public: HybridSignPublic {
				ml_dsa: ml_dsa_public.into_bytes(),
				slh_dsa: slh_dsa_public.into_bytes(),
				ed25519: ed25519.verifying_key(),
			},
			ed25519,
		}
	}

	/// Sign the message and return
	/// `ml_dsa_87_signature||slh_dsa_sha2_256s_signature||ed25519_signature`.
	///
	/// # Errors
	///
	/// Returns [`HybridError::SigningFailed`] if ML-DSA-87 or SLH-DSA signing
	/// fails.
	pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HybridError> {
		let ml_dsa_signature = self
			.ml_dsa
			.try_sign_with_seed(
				&bytes_os_rng::<DERIVED_SECRET_LEN>(),
				message,
				SIGNING_DOMAIN,
			)
			.map_err(|_| HybridError::SigningFailed)?;
		let slh_dsa_signature = self
			.slh_dsa
			.try_sign(message, SIGNING_DOMAIN, true)
			.map_err(|_| HybridError::SigningFailed)?;
		let ed25519_signature =
			self.ed25519.sign(&ed25519_message(message)).to_bytes();

		let mut signature = Vec::with_capacity(SIGNATURE_LEN);
		signature.extend_from_slice(&ml_dsa_signature);
		signature.extend_from_slice(&slh_dsa_signature);
		signature.extend_from_slice(&ed25519_signature);
		Ok(signature)
	}

	/// Get the public key of this pair.
	#[must_use]
	pub fn public_key(&self) -> HybridSignPublic {
		self.public.clone()
	}
}

fn ed25519_message(message: &[u8]) -> Vec<u8> {
	let mut domain_separated =
		Vec::with_capacity(SIGNING_DOMAIN.len() + message.len());
	domain_separated.extend_from_slice(SIGNING_DOMAIN);
	domain_separated.extend_from_slice(message);
	domain_separated
}

/// ML-DSA-87 + SLH-DSA-SHA2-256s + Ed25519 verifying key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignPublic {
	ml_dsa: [u8; ML_DSA_PUBLIC_LEN],
	slh_dsa: [u8; SLH_DSA_PUBLIC_LEN],
	ed25519: VerifyingKey,
}

impl HybridSignPublic {
	/// Verify `signature` over `message`: all three parts must verify.
	///
	/// # Errors
	///
	/// Returns [`HybridError::FailedToDeserializeSignature`] if the signature
	/// has the wrong length, and [`HybridError::FailedSignatureVerification`]
	/// if any part does not verify.
	pub fn verify(
		&self,
		message: &[u8],
		signature: &[u8],
	) -> Result<(), HybridError> {
		if signature.len() != SIGNATURE_LEN {
			return Err(HybridError::FailedToDeserializeSignature);
		}
		let (ml_dsa_signature, rest) = signature.split_at(ML_DSA_SIGNATURE_LEN);
		let (slh_dsa_signature, ed25519_signature) =
			rest.split_at(SLH_DSA_SIGNATURE_LEN);
		let ml_dsa_signature: &[u8; ML_DSA_SIGNATURE_LEN] = ml_dsa_signature
			.try_into()
			.map_err(|_| HybridError::FailedToDeserializeSignature)?;
		let slh_dsa_signature: &[u8; SLH_DSA_SIGNATURE_LEN] = slh_dsa_signature
			.try_into()
			.map_err(|_| HybridError::FailedToDeserializeSignature)?;
		let ed25519_signature: &[u8; ED25519_SIGNATURE_LEN] = ed25519_signature
			.try_into()
			.map_err(|_| HybridError::FailedToDeserializeSignature)?;

		let ml_dsa = ml_dsa_87::PublicKey::try_from_bytes(self.ml_dsa)
			.map_err(|_| HybridError::FailedToReadPublicKey)?;
		let slh_dsa =
			slh_dsa_sha2_256s::PublicKey::try_from_bytes(self.slh_dsa)
				.map_err(|_| HybridError::FailedToReadPublicKey)?;
		let ml_dsa_verifies =
			ml_dsa.verify(message, ml_dsa_signature, SIGNING_DOMAIN);
		let slh_dsa_verifies =
			slh_dsa.verify(message, slh_dsa_signature, SIGNING_DOMAIN);
		let ed25519_verifies = self
			.ed25519
			.verify_strict(
				&ed25519_message(message),
				&Ed25519Signature::from_bytes(ed25519_signature),
			)
			.is_ok();

		if ml_dsa_verifies && slh_dsa_verifies && ed25519_verifies {
			Ok(())
		} else {
			Err(HybridError::FailedSignatureVerification)
		}
	}

	/// Serialize as
	/// `ml_dsa_87_public||slh_dsa_sha2_256s_public||ed25519_public`.
	#[must_use]
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(SIGN_PUBLIC_LEN);
		bytes.extend_from_slice(&self.ml_dsa);
		bytes.extend_from_slice(&self.slh_dsa);
		bytes.extend_from_slice(self.ed25519.as_bytes());
		bytes
	}

	/// Deserialize from
	/// `ml_dsa_87_public||slh_dsa_sha2_256s_public||ed25519_public`.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if the bytes are the wrong length, a part is
	/// not a valid key, or the Ed25519 key has small order.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
		if bytes.len() > SIGN_PUBLIC_LEN {
			return Err(HybridError::EncodedPublicKeyTooLong);
		}
		if bytes.len() < SIGN_PUBLIC_LEN {
			return Err(HybridError::EncodedPublicKeyTooShort);
		}
		let (ml_dsa, rest) = bytes.split_at(ML_DSA_PUBLIC_LEN);
		let (slh_dsa, ed25519) = rest.split_at(SLH_DSA_PUBLIC_LEN);
		let ml_dsa: [u8; ML_DSA_PUBLIC_LEN] = ml_dsa
			.try_into()
			.map_err(|_| HybridError::EncodedPublicKeyTooShort)?;
		ml_dsa_87::PublicKey::try_from_bytes(ml_dsa)
			.map_err(|_| HybridError::FailedToReadPublicKey)?;
		let slh_dsa: [u8; SLH_DSA_PUBLIC_LEN] = slh_dsa
			.try_into()
			.map_err(|_| HybridError::EncodedPublicKeyTooShort)?;
		slh_dsa_sha2_256s::PublicKey::try_from_bytes(slh_dsa)
			.map_err(|_| HybridError::FailedToReadPublicKey)?;
		let ed25519: &[u8; ED25519_PUBLIC_LEN] = ed25519
			.try_into()
			.map_err(|_| HybridError::EncodedPublicKeyTooShort)?;
		let ed25519 = VerifyingKey::from_bytes(ed25519)
			.map_err(|_| HybridError::FailedToReadPublicKey)?;
		if ed25519.is_weak() {
			return Err(HybridError::FailedToReadPublicKey);
		}

		Ok(Self { ml_dsa, slh_dsa, ed25519 })
	}
}

#[cfg(test)]
mod test {
	use super::*;

	const SLH_DSA_AT: usize = ML_DSA_SIGNATURE_LEN;
	const ED25519_AT: usize = ML_DSA_SIGNATURE_LEN + SLH_DSA_SIGNATURE_LEN;

	struct Seeds {
		ml_dsa_xi: Zeroizing<[u8; DERIVED_SECRET_LEN]>,
		slh_dsa: [Zeroizing<[u8; DERIVED_SECRET_LEN]>; 3],
		ed25519: Zeroizing<[u8; DERIVED_SECRET_LEN]>,
	}

	impl Seeds {
		fn random() -> Self {
			Self {
				ml_dsa_xi: bytes_os_rng(),
				slh_dsa: [bytes_os_rng(), bytes_os_rng(), bytes_os_rng()],
				ed25519: bytes_os_rng(),
			}
		}

		fn pair(&self) -> HybridSignPair {
			HybridSignPair::from_seeds(
				&self.ml_dsa_xi,
				&SlhDsaSeeds {
					secret_seed: &self.slh_dsa[0],
					secret_prf: &self.slh_dsa[1],
					public_seed: &self.slh_dsa[2],
				},
				&self.ed25519,
			)
		}
	}

	fn pair() -> HybridSignPair {
		Seeds::random().pair()
	}

	#[test]
	fn sign_and_verify() {
		let pair = pair();
		let signature = pair.sign(b"message").unwrap();

		assert_eq!(signature.len(), SIGNATURE_LEN);
		assert!(pair.public_key().verify(b"message", &signature).is_ok());
	}

	#[test]
	fn signatures_are_hedged() {
		let pair = pair();
		let first = pair.sign(b"message").unwrap();
		let second = pair.sign(b"message").unwrap();

		assert_ne!(
			first[..SLH_DSA_AT],
			second[..SLH_DSA_AT],
			"ML-DSA-87 must draw fresh signing randomness"
		);
		assert_ne!(
			first[SLH_DSA_AT..ED25519_AT],
			second[SLH_DSA_AT..ED25519_AT],
			"SLH-DSA must draw fresh signing randomness"
		);
	}

	#[test]
	fn tampered_ml_dsa_part_fails() {
		let pair = pair();
		let mut signature = pair.sign(b"message").unwrap();
		signature[0] ^= 1;

		assert_eq!(
			pair.public_key().verify(b"message", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification,
			"valid SLH-DSA and Ed25519 parts must not carry a broken ML-DSA-87 part"
		);
	}

	#[test]
	fn tampered_slh_dsa_part_fails() {
		let pair = pair();
		let mut signature = pair.sign(b"message").unwrap();
		signature[SLH_DSA_AT] ^= 1;

		assert_eq!(
			pair.public_key().verify(b"message", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification,
			"valid ML-DSA-87 and Ed25519 parts must not carry a broken SLH-DSA part"
		);
	}

	#[test]
	fn tampered_ed25519_part_fails() {
		let pair = pair();
		let mut signature = pair.sign(b"message").unwrap();
		*signature.last_mut().unwrap() ^= 1;

		assert_eq!(
			pair.public_key().verify(b"message", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification,
			"valid ML-DSA-87 and SLH-DSA parts must not carry a broken Ed25519 part"
		);
	}

	#[test]
	fn slh_dsa_part_from_another_key_fails() {
		let (pair, other) = (pair(), pair());
		let mut signature = pair.sign(b"message").unwrap();
		let other_signature = other.sign(b"message").unwrap();
		signature[SLH_DSA_AT..ED25519_AT]
			.copy_from_slice(&other_signature[SLH_DSA_AT..ED25519_AT]);

		assert_eq!(
			pair.public_key().verify(b"message", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification
		);
	}

	#[test]
	fn ed25519_part_from_another_key_fails() {
		let (pair, other) = (pair(), pair());
		let mut signature = pair.sign(b"message").unwrap();
		let other_signature = other.sign(b"message").unwrap();
		signature[ED25519_AT..].copy_from_slice(&other_signature[ED25519_AT..]);

		assert_eq!(
			pair.public_key().verify(b"message", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification
		);
	}

	#[test]
	fn plain_ed25519_signature_does_not_verify() {
		let seeds = Seeds::random();
		let pair = seeds.pair();
		let mut signature = pair.sign(b"message").unwrap();
		let plain =
			SigningKey::from_bytes(&seeds.ed25519).sign(b"message").to_bytes();
		signature[ED25519_AT..].copy_from_slice(&plain);

		assert_eq!(
			pair.public_key().verify(b"message", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification,
			"the Ed25519 part signs the domain-separated message only"
		);
	}

	#[test]
	fn slh_dsa_signature_without_the_domain_does_not_verify() {
		let seeds = Seeds::random();
		let pair = seeds.pair();
		let mut signature = pair.sign(b"message").unwrap();
		let (_, slh_dsa) = slh_dsa_sha2_256s::KG::keygen_from_seed(
			&seeds.slh_dsa[0],
			&seeds.slh_dsa[1],
			&seeds.slh_dsa[2],
		);
		let plain = slh_dsa.try_sign(b"message", b"", true).unwrap();
		signature[SLH_DSA_AT..ED25519_AT].copy_from_slice(&plain);

		assert_eq!(
			pair.public_key().verify(b"message", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification,
			"the SLH-DSA part is bound to the signing domain as its context"
		);
	}

	#[test]
	fn wrong_length_signature_is_rejected() {
		let pair = pair();
		let signature = pair.sign(b"message").unwrap();

		assert_eq!(
			pair.public_key().verify(b"message", &signature[1..]).unwrap_err(),
			HybridError::FailedToDeserializeSignature
		);
	}

	#[test]
	fn small_order_ed25519_key_is_rejected() {
		let pair = pair();
		let mut bytes = pair.public_key().to_bytes();
		let ed25519_at = ML_DSA_PUBLIC_LEN + SLH_DSA_PUBLIC_LEN;
		bytes[ed25519_at..].copy_from_slice(&[0u8; ED25519_PUBLIC_LEN]);
		bytes[ed25519_at] = 1;

		assert_eq!(
			HybridSignPublic::from_bytes(&bytes).unwrap_err(),
			HybridError::FailedToReadPublicKey,
			"the Ed25519 identity point would accept forged signatures"
		);
	}

	#[test]
	fn public_key_roundtrip_bytes() {
		let pair = pair();
		let public2 =
			HybridSignPublic::from_bytes(&pair.public_key().to_bytes())
				.unwrap();
		let signature = pair.sign(b"message").unwrap();

		assert!(public2.verify(b"message", &signature).is_ok());
	}
}
