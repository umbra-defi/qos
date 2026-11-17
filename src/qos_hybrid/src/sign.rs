//! Hybrid ML-DSA-87 + Ed25519 signing and verification.
//!
//! A signature is `ml_dsa_87_signature||ed25519_signature`, and verifies only
//! if both halves verify, so a forger has to break both schemes. Both halves
//! are bound to [`SIGNING_DOMAIN`]: it is the ML-DSA-87 context string and
//! prefixes the message Ed25519 signs, so neither half verifies as a plain
//! signature of either scheme.
//!
//! ML-DSA-87 signatures are hedged: each one mixes 32 fresh random bytes into
//! the signing nonce (FIPS 204 hedged variant), so two signatures over the
//! same message differ while both verify. Ed25519 verification is strict
//! (`verify_strict`), refusing small-order keys and non-canonical encodings.

use ed25519_dalek::{
	Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey,
};
use fips204::{
	ml_dsa_87,
	traits::{KeyGen, SerDes, Signer, Verifier},
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
	DERIVED_SECRET_LEN, ED25519_PUBLIC_LEN, ED25519_SIGNATURE_LEN, HybridError,
	ML_DSA_PUBLIC_LEN, ML_DSA_SIGNATURE_LEN, SIGN_PUBLIC_LEN, SIGNATURE_LEN,
	bytes_os_rng,
};

/// Domain both signature halves are bound to.
pub const SIGNING_DOMAIN: &[u8] = b"qos_hybrid_ml_dsa_87_ed25519_v1";

/// ML-DSA-87 + Ed25519 signing key pair.
#[derive(ZeroizeOnDrop)]
pub struct HybridSignPair {
	ml_dsa: ml_dsa_87::PrivateKey,
	ed25519: SigningKey,
	#[zeroize(skip)]
	public: HybridSignPublic,
}

impl HybridSignPair {
	/// Build the pair from the ML-DSA-87 `xi` seed and the Ed25519 seed.
	#[must_use]
	pub fn from_seeds(
		ml_dsa_xi: &Zeroizing<[u8; DERIVED_SECRET_LEN]>,
		ed25519_seed: &Zeroizing<[u8; DERIVED_SECRET_LEN]>,
	) -> Self {
		let (ml_dsa_public, ml_dsa) =
			ml_dsa_87::KG::keygen_from_seed(ml_dsa_xi);
		let ed25519 = SigningKey::from_bytes(ed25519_seed);

		Self {
			ml_dsa,
			public: HybridSignPublic {
				ml_dsa: ml_dsa_public.into_bytes(),
				ed25519: ed25519.verifying_key(),
			},
			ed25519,
		}
	}

	/// Sign the message and return `ml_dsa_87_signature||ed25519_signature`.
	///
	/// # Errors
	///
	/// Returns [`HybridError::SigningFailed`] if ML-DSA-87 signing fails.
	pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HybridError> {
		let ml_dsa_signature = self
			.ml_dsa
			.try_sign_with_seed(
				&bytes_os_rng::<DERIVED_SECRET_LEN>(),
				message,
				SIGNING_DOMAIN,
			)
			.map_err(|_| HybridError::SigningFailed)?;
		let ed25519_signature =
			self.ed25519.sign(&ed25519_message(message)).to_bytes();

		let mut signature = Vec::with_capacity(SIGNATURE_LEN);
		signature.extend_from_slice(&ml_dsa_signature);
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

/// ML-DSA-87 + Ed25519 verifying key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignPublic {
	ml_dsa: [u8; ML_DSA_PUBLIC_LEN],
	ed25519: VerifyingKey,
}

impl HybridSignPublic {
	/// Verify `signature` over `message`: both halves must verify.
	///
	/// # Errors
	///
	/// Returns [`HybridError::FailedToDeserializeSignature`] if the signature
	/// has the wrong length, and [`HybridError::FailedSignatureVerification`]
	/// if either half does not verify.
	pub fn verify(
		&self,
		message: &[u8],
		signature: &[u8],
	) -> Result<(), HybridError> {
		if signature.len() != SIGNATURE_LEN {
			return Err(HybridError::FailedToDeserializeSignature);
		}
		let (ml_dsa_signature, ed25519_signature) =
			signature.split_at(ML_DSA_SIGNATURE_LEN);
		let ml_dsa_signature: &[u8; ML_DSA_SIGNATURE_LEN] = ml_dsa_signature
			.try_into()
			.map_err(|_| HybridError::FailedToDeserializeSignature)?;
		let ed25519_signature: &[u8; ED25519_SIGNATURE_LEN] = ed25519_signature
			.try_into()
			.map_err(|_| HybridError::FailedToDeserializeSignature)?;

		let ml_dsa = ml_dsa_87::PublicKey::try_from_bytes(self.ml_dsa)
			.map_err(|_| HybridError::FailedToReadPublicKey)?;
		let ml_dsa_verifies =
			ml_dsa.verify(message, ml_dsa_signature, SIGNING_DOMAIN);
		let ed25519_verifies = self
			.ed25519
			.verify_strict(
				&ed25519_message(message),
				&Ed25519Signature::from_bytes(ed25519_signature),
			)
			.is_ok();

		if ml_dsa_verifies && ed25519_verifies {
			Ok(())
		} else {
			Err(HybridError::FailedSignatureVerification)
		}
	}

	/// Serialize as `ml_dsa_87_public||ed25519_public`.
	#[must_use]
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(SIGN_PUBLIC_LEN);
		bytes.extend_from_slice(&self.ml_dsa);
		bytes.extend_from_slice(self.ed25519.as_bytes());
		bytes
	}

	/// Deserialize from `ml_dsa_87_public||ed25519_public`.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if the bytes are the wrong length, a half is
	/// not a valid key, or the Ed25519 key has small order.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
		if bytes.len() > SIGN_PUBLIC_LEN {
			return Err(HybridError::EncodedPublicKeyTooLong);
		}
		if bytes.len() < SIGN_PUBLIC_LEN {
			return Err(HybridError::EncodedPublicKeyTooShort);
		}
		let (ml_dsa, ed25519) = bytes.split_at(ML_DSA_PUBLIC_LEN);
		let ml_dsa: [u8; ML_DSA_PUBLIC_LEN] = ml_dsa
			.try_into()
			.map_err(|_| HybridError::EncodedPublicKeyTooShort)?;
		ml_dsa_87::PublicKey::try_from_bytes(ml_dsa)
			.map_err(|_| HybridError::FailedToReadPublicKey)?;
		let ed25519: &[u8; ED25519_PUBLIC_LEN] = ed25519
			.try_into()
			.map_err(|_| HybridError::EncodedPublicKeyTooShort)?;
		let ed25519 = VerifyingKey::from_bytes(ed25519)
			.map_err(|_| HybridError::FailedToReadPublicKey)?;
		if ed25519.is_weak() {
			return Err(HybridError::FailedToReadPublicKey);
		}

		Ok(Self { ml_dsa, ed25519 })
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn pair() -> HybridSignPair {
		HybridSignPair::from_seeds(
			&bytes_os_rng::<DERIVED_SECRET_LEN>(),
			&bytes_os_rng::<DERIVED_SECRET_LEN>(),
		)
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

		assert_ne!(
			pair.sign(b"message").unwrap(),
			pair.sign(b"message").unwrap()
		);
	}

	#[test]
	fn tampered_ml_dsa_half_fails() {
		let pair = pair();
		let mut signature = pair.sign(b"message").unwrap();
		signature[0] ^= 1;

		assert_eq!(
			pair.public_key().verify(b"message", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification,
			"a valid Ed25519 half must not carry a broken ML-DSA-87 half"
		);
	}

	#[test]
	fn tampered_ed25519_half_fails() {
		let pair = pair();
		let mut signature = pair.sign(b"message").unwrap();
		*signature.last_mut().unwrap() ^= 1;

		assert_eq!(
			pair.public_key().verify(b"message", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification,
			"a valid ML-DSA-87 half must not carry a broken Ed25519 half"
		);
	}

	#[test]
	fn halves_from_another_key_fail() {
		let (pair, other) = (pair(), pair());
		let mut signature = pair.sign(b"message").unwrap();
		let other_signature = other.sign(b"message").unwrap();
		signature[ML_DSA_SIGNATURE_LEN..]
			.copy_from_slice(&other_signature[ML_DSA_SIGNATURE_LEN..]);

		assert_eq!(
			pair.public_key().verify(b"message", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification
		);
	}

	#[test]
	fn plain_ed25519_signature_does_not_verify() {
		let seed = bytes_os_rng::<DERIVED_SECRET_LEN>();
		let pair = HybridSignPair::from_seeds(
			&bytes_os_rng::<DERIVED_SECRET_LEN>(),
			&seed,
		);
		let mut signature = pair.sign(b"message").unwrap();
		let plain = SigningKey::from_bytes(&seed).sign(b"message").to_bytes();
		signature[ML_DSA_SIGNATURE_LEN..].copy_from_slice(&plain);

		assert_eq!(
			pair.public_key().verify(b"message", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification,
			"the Ed25519 half signs the domain-separated message only"
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
		bytes[ML_DSA_PUBLIC_LEN..].copy_from_slice(&[0u8; ED25519_PUBLIC_LEN]);
		bytes[ML_DSA_PUBLIC_LEN] = 1;

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
