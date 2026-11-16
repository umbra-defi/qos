//! ML-DSA-87 signing and verification.
//!
//! Signatures are hedged: each one mixes 32 fresh random bytes into the
//! signing nonce (FIPS 204 hedged variant), so two signatures over the same
//! message differ while both verify. Every signature is bound to
//! [`SIGNING_CONTEXT`].

use fips204::{
	ml_dsa_87,
	traits::{KeyGen, SerDes, Signer, Verifier},
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
	DERIVED_SECRET_LEN, HybridError, SIGN_PUBLIC_LEN, SIGNATURE_LEN,
	bytes_os_rng,
};

/// FIPS 204 context string every qos hybrid signature is bound to.
pub const SIGNING_CONTEXT: &[u8] = b"qos_hybrid_ml_dsa_87_v1";

/// ML-DSA-87 signing key pair.
#[derive(ZeroizeOnDrop)]
pub struct MlDsaSignPair {
	private: ml_dsa_87::PrivateKey,
	#[zeroize(skip)]
	public: MlDsaSignPublic,
}

impl MlDsaSignPair {
	/// Build the pair from the ML-DSA-87 `xi` seed.
	#[must_use]
	pub fn from_seed(xi: &Zeroizing<[u8; DERIVED_SECRET_LEN]>) -> Self {
		let (public, private) = ml_dsa_87::KG::keygen_from_seed(xi);

		Self {
			private,
			public: MlDsaSignPublic { public: public.into_bytes() },
		}
	}

	/// Sign the message and return the raw signature.
	///
	/// # Errors
	///
	/// Returns [`HybridError::SigningFailed`] if signing fails.
	pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HybridError> {
		self.private
			.try_sign_with_seed(
				&bytes_os_rng::<DERIVED_SECRET_LEN>(),
				message,
				SIGNING_CONTEXT,
			)
			.map(|signature| signature.to_vec())
			.map_err(|_| HybridError::SigningFailed)
	}

	/// Get the public key of this pair.
	#[must_use]
	pub fn public_key(&self) -> MlDsaSignPublic {
		self.public.clone()
	}
}

/// ML-DSA-87 verifying key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaSignPublic {
	public: [u8; SIGN_PUBLIC_LEN],
}

impl MlDsaSignPublic {
	/// Verify `signature` over `message`.
	///
	/// # Errors
	///
	/// Returns [`HybridError::FailedToDeserializeSignature`] if the signature
	/// has the wrong length, and [`HybridError::FailedSignatureVerification`]
	/// if it does not verify.
	pub fn verify(
		&self,
		message: &[u8],
		signature: &[u8],
	) -> Result<(), HybridError> {
		let signature: &[u8; SIGNATURE_LEN] = signature
			.try_into()
			.map_err(|_| HybridError::FailedToDeserializeSignature)?;
		let public = ml_dsa_87::PublicKey::try_from_bytes(self.public)
			.map_err(|_| HybridError::FailedToReadPublicKey)?;

		if public.verify(message, signature, SIGNING_CONTEXT) {
			Ok(())
		} else {
			Err(HybridError::FailedSignatureVerification)
		}
	}

	/// Serialize to the FIPS 204 public key encoding.
	#[must_use]
	pub fn to_bytes(&self) -> Vec<u8> {
		self.public.to_vec()
	}

	/// Deserialize from the FIPS 204 public key encoding.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if the bytes are the wrong length or not a
	/// valid ML-DSA-87 public key.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
		if bytes.len() > SIGN_PUBLIC_LEN {
			return Err(HybridError::EncodedPublicKeyTooLong);
		}
		let public: [u8; SIGN_PUBLIC_LEN] = bytes
			.try_into()
			.map_err(|_| HybridError::EncodedPublicKeyTooShort)?;
		ml_dsa_87::PublicKey::try_from_bytes(public)
			.map_err(|_| HybridError::FailedToReadPublicKey)?;

		Ok(Self { public })
	}
}

#[cfg(test)]
mod test {
	use super::*;

	fn pair() -> MlDsaSignPair {
		MlDsaSignPair::from_seed(&bytes_os_rng::<DERIVED_SECRET_LEN>())
	}

	#[test]
	fn sign_and_verify() {
		let pair = pair();
		let signature = pair.sign(b"message").unwrap();

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
	fn tampered_signature_fails() {
		let pair = pair();
		let mut signature = pair.sign(b"message").unwrap();
		signature[0] ^= 1;

		assert_eq!(
			pair.public_key().verify(b"message", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification
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
	fn public_key_roundtrip_bytes() {
		let pair = pair();
		let public2 =
			MlDsaSignPublic::from_bytes(&pair.public_key().to_bytes()).unwrap();
		let signature = pair.sign(b"message").unwrap();

		assert!(public2.verify(b"message", &signature).is_ok());
	}
}
