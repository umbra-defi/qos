//! Hybrid ML-KEM-1024 + X25519 public key encryption, and the AES-256-GCM
//! symmetric secret.
//!
//! A sender encapsulates to the receiver's ML-KEM-1024 key and runs X25519
//! against the receiver's X25519 key from a fresh ephemeral secret. Both shared
//! secrets feed HKDF-SHA512, salted with [`COMBINER_SALT`], whose info is the
//! SHA-512 transcript digest
//! `SHA512(ephemeral_x25519_public||ml_kem_ciphertext||receiver_public)`.
//! The 32-byte output keys AES-256-GCM, with the transcript digest as AAD.
//! Every transcript field has a fixed length, so the concatenation is
//! unambiguous without length prefixes.

use aes_gcm::{
	Aes256Gcm, Nonce,
	aead::{Aead, KeyInit, Payload},
};
use borsh::{BorshDeserialize, BorshSerialize};
use fips203::{
	ml_kem_1024,
	traits::{Decaps, Encaps, KeyGen, SerDes},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
	DERIVED_SECRET_LEN, ENCRYPT_PUBLIC_LEN, HybridError, ML_KEM_CIPHERTEXT_LEN,
	ML_KEM_PUBLIC_LEN, X25519_PUBLIC_LEN, bytes_os_rng,
};

const AES256_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TRANSCRIPT_DIGEST_LEN: usize = 64;
/// HKDF-SHA512 salt of the hybrid KEM combiner.
pub const COMBINER_SALT: &[u8] = b"qos_hybrid_ml_kem_1024_x25519_combiner_v1";
const AES_GCM_256_SYMMETRIC_AAD: &[u8] = b"qos_hybrid_aes_gcm_256_symmetric";

/// Envelope for serializing a message encrypted to a hybrid public key.
#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct Envelope {
	/// Nonce used as an input to the cipher.
	nonce: [u8; NONCE_LEN],
	/// The sender's ephemeral X25519 public key.
	pub ephemeral_x25519_public: [u8; X25519_PUBLIC_LEN],
	/// The ML-KEM-1024 ciphertext encapsulated to the receiver.
	pub ml_kem_ciphertext: [u8; ML_KEM_CIPHERTEXT_LEN],
	/// The data encrypted with an AES 256 GCM cipher.
	encrypted_message: Vec<u8>,
}

/// Hybrid decryption key: an ML-KEM-1024 decapsulation key and an X25519
/// secret.
#[derive(ZeroizeOnDrop)]
pub struct HybridEncryptPair {
	ml_kem_private: ml_kem_1024::DecapsKey,
	x25519_private: StaticSecret,
	#[zeroize(skip)]
	public: HybridEncryptPublic,
}

impl HybridEncryptPair {
	/// Build the pair from the ML-KEM-1024 `d` and `z` seeds and the X25519
	/// secret.
	#[must_use]
	pub fn from_seeds(
		ml_kem_d: &Zeroizing<[u8; DERIVED_SECRET_LEN]>,
		ml_kem_z: &Zeroizing<[u8; DERIVED_SECRET_LEN]>,
		x25519: &Zeroizing<[u8; DERIVED_SECRET_LEN]>,
	) -> Self {
		let (ml_kem_public, ml_kem_private) =
			ml_kem_1024::KG::keygen_from_seed(**ml_kem_d, **ml_kem_z);
		let x25519_private = StaticSecret::from(**x25519);
		let public = HybridEncryptPublic {
			ml_kem_public: ml_kem_public.into_bytes(),
			x25519_public: X25519Public::from(&x25519_private).to_bytes(),
		};

		Self { ml_kem_private, x25519_private, public }
	}

	/// Decrypt a message encrypted to this pair's public key.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if the envelope cannot be deserialized, a key
	/// exchange fails, or decryption fails.
	pub fn decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Zeroizing<Vec<u8>>, HybridError> {
		let Envelope {
			nonce,
			ephemeral_x25519_public,
			ml_kem_ciphertext,
			encrypted_message,
		} = Envelope::try_from_slice(serialized_envelope)
			.map_err(|_| HybridError::FailedToDeserializeEnvelope)?;

		let ciphertext =
			ml_kem_1024::CipherText::try_from_bytes(ml_kem_ciphertext)
				.map_err(|_| HybridError::FailedToDeserializeEnvelope)?;
		let ml_kem_shared = Zeroizing::new(
			self.ml_kem_private
				.try_decaps(&ciphertext)
				.map_err(|_| HybridError::MlKemDecapsulationFailed)?
				.into_bytes(),
		);

		let x25519_shared = self
			.x25519_private
			.diffie_hellman(&X25519Public::from(ephemeral_x25519_public));
		if !x25519_shared.was_contributory() {
			return Err(HybridError::NonContributoryX25519Exchange);
		}

		let transcript = transcript_digest(
			&ephemeral_x25519_public,
			&ml_kem_ciphertext,
			&self.public.to_bytes(),
		);
		let cipher = create_cipher(
			&ml_kem_shared,
			x25519_shared.as_bytes(),
			&transcript,
		)?;
		let payload = Payload { aad: &transcript, msg: &encrypted_message };

		cipher
			.decrypt(Nonce::from_slice(&nonce), payload)
			.map(Zeroizing::new)
			.map_err(|_| HybridError::AesGcm256DecryptError)
	}

	/// Get the public key.
	#[must_use]
	pub fn public_key(&self) -> HybridEncryptPublic {
		self.public.clone()
	}
}

/// Hybrid encryption public key: an ML-KEM-1024 encapsulation key and an
/// X25519 public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridEncryptPublic {
	ml_kem_public: [u8; ML_KEM_PUBLIC_LEN],
	x25519_public: [u8; X25519_PUBLIC_LEN],
}

impl HybridEncryptPublic {
	/// Encrypt a message to this public key.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if the key is malformed, the X25519 exchange is
	/// not contributory, or encryption fails.
	pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, HybridError> {
		let ml_kem_public =
			ml_kem_1024::EncapsKey::try_from_bytes(self.ml_kem_public)
				.map_err(|_| HybridError::FailedToReadPublicKey)?;
		let (ml_kem_shared, ciphertext) = ml_kem_public
			.encaps_from_seed(&bytes_os_rng::<DERIVED_SECRET_LEN>());
		let ml_kem_shared = Zeroizing::new(ml_kem_shared.into_bytes());
		let ml_kem_ciphertext = ciphertext.into_bytes();

		let ephemeral_secret = StaticSecret::random();
		let ephemeral_x25519_public =
			X25519Public::from(&ephemeral_secret).to_bytes();
		let x25519_shared = ephemeral_secret
			.diffie_hellman(&X25519Public::from(self.x25519_public));
		if !x25519_shared.was_contributory() {
			return Err(HybridError::NonContributoryX25519Exchange);
		}

		let transcript = transcript_digest(
			&ephemeral_x25519_public,
			&ml_kem_ciphertext,
			&self.to_bytes(),
		);
		let cipher = create_cipher(
			&ml_kem_shared,
			x25519_shared.as_bytes(),
			&transcript,
		)?;

		let nonce = *bytes_os_rng::<NONCE_LEN>();
		let payload = Payload { aad: &transcript, msg: message };
		let encrypted_message = cipher
			.encrypt(Nonce::from_slice(&nonce), payload)
			.map_err(|_| HybridError::AesGcm256EncryptError)?;

		borsh::to_vec(&Envelope {
			nonce,
			ephemeral_x25519_public,
			ml_kem_ciphertext,
			encrypted_message,
		})
		.map_err(|_| HybridError::FailedToSerializeEnvelope)
	}

	/// Serialize as `ml_kem_public||x25519_public`.
	#[must_use]
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(ENCRYPT_PUBLIC_LEN);
		bytes.extend_from_slice(&self.ml_kem_public);
		bytes.extend_from_slice(&self.x25519_public);
		bytes
	}

	/// Deserialize from `ml_kem_public||x25519_public`, checking the ML-KEM
	/// key's encoding.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if the bytes are the wrong length or the
	/// ML-KEM-1024 key is malformed.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
		if bytes.len() > ENCRYPT_PUBLIC_LEN {
			return Err(HybridError::EncodedPublicKeyTooLong);
		}
		if bytes.len() < ENCRYPT_PUBLIC_LEN {
			return Err(HybridError::EncodedPublicKeyTooShort);
		}

		let (ml_kem_bytes, x25519_bytes) = bytes.split_at(ML_KEM_PUBLIC_LEN);
		let ml_kem_public: [u8; ML_KEM_PUBLIC_LEN] = ml_kem_bytes
			.try_into()
			.map_err(|_| HybridError::FailedToReadPublicKey)?;
		ml_kem_1024::EncapsKey::try_from_bytes(ml_kem_public)
			.map_err(|_| HybridError::FailedToReadPublicKey)?;

		Ok(Self {
			ml_kem_public,
			x25519_public: x25519_bytes
				.try_into()
				.map_err(|_| HybridError::FailedToReadPublicKey)?,
		})
	}
}

fn transcript_digest(
	ephemeral_x25519_public: &[u8; X25519_PUBLIC_LEN],
	ml_kem_ciphertext: &[u8; ML_KEM_CIPHERTEXT_LEN],
	receiver_public: &[u8],
) -> [u8; TRANSCRIPT_DIGEST_LEN] {
	let mut hasher = Sha512::new();
	hasher.update(ephemeral_x25519_public);
	hasher.update(ml_kem_ciphertext);
	hasher.update(receiver_public);
	hasher.finalize().into()
}

fn create_cipher(
	ml_kem_shared: &[u8; 32],
	x25519_shared: &[u8; 32],
	transcript: &[u8; TRANSCRIPT_DIGEST_LEN],
) -> Result<Aes256Gcm, HybridError> {
	let mut input_key_material = Zeroizing::new([0u8; 64]);
	input_key_material[..32].copy_from_slice(ml_kem_shared);
	input_key_material[32..].copy_from_slice(x25519_shared);

	let hk = Hkdf::<Sha512>::new(Some(COMBINER_SALT), &input_key_material[..]);
	let mut shared_key = Zeroizing::new([0u8; AES256_KEY_LEN]);
	hk.expand(transcript, &mut *shared_key)
		.map_err(|_| HybridError::HkdfExpansionFailed)?;

	Aes256Gcm::new_from_slice(&shared_key[..])
		.map_err(|_| HybridError::FailedToCreateAes256GcmCipher)
}

/// Envelope for holding a symmetrically encrypted message and the nonce
/// needed to decrypt it.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct SymmetricEnvelope {
	/// Nonce used by the cipher.
	pub nonce: [u8; NONCE_LEN],
	/// The ciphertext.
	pub encrypted_message: Vec<u8>,
}

/// Secret for performing encryption and decryption using a AES GCM 256 Cipher.
#[cfg_attr(any(feature = "mock", test), derive(Clone, PartialEq, Eq))]
pub struct AesGcm256Secret {
	secret: Zeroizing<[u8; AES256_KEY_LEN]>,
}

impl Zeroize for AesGcm256Secret {
	fn zeroize(&mut self) {
		self.secret.zeroize();
	}
}

impl AesGcm256Secret {
	/// Generate a secret.
	#[must_use]
	pub fn generate() -> Self {
		Self { secret: bytes_os_rng::<AES256_KEY_LEN>() }
	}

	/// The secret as bytes.
	#[must_use]
	pub fn to_bytes(&self) -> &Zeroizing<[u8; AES256_KEY_LEN]> {
		&self.secret
	}

	/// Create [`Self`] from bytes.
	#[must_use]
	pub fn from_bytes(bytes: &Zeroizing<[u8; AES256_KEY_LEN]>) -> Self {
		Self { secret: bytes.clone() }
	}

	/// Encrypt the given `msg`, returning a serialized [`SymmetricEnvelope`].
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if encryption or envelope serialization fails.
	pub fn encrypt(&self, msg: &[u8]) -> Result<Vec<u8>, HybridError> {
		let nonce = *bytes_os_rng::<NONCE_LEN>();
		let payload = Payload { aad: AES_GCM_256_SYMMETRIC_AAD, msg };

		let encrypted_message = Aes256Gcm::new_from_slice(&self.secret[..])
			.map_err(|_| HybridError::FailedToCreateAes256GcmCipher)?
			.encrypt(Nonce::from_slice(&nonce), payload)
			.map_err(|_| HybridError::AesGcm256EncryptError)?;

		borsh::to_vec(&SymmetricEnvelope { nonce, encrypted_message })
			.map_err(|_| HybridError::FailedToSerializeEnvelope)
	}

	/// Decrypt the given serialized [`SymmetricEnvelope`], returning the
	/// plaintext.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if the envelope cannot be deserialized or
	/// decryption fails.
	pub fn decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Zeroizing<Vec<u8>>, HybridError> {
		let SymmetricEnvelope { nonce, encrypted_message } =
			SymmetricEnvelope::try_from_slice(serialized_envelope)
				.map_err(|_| HybridError::FailedToDeserializeEnvelope)?;

		let payload =
			Payload { aad: AES_GCM_256_SYMMETRIC_AAD, msg: &encrypted_message };

		Aes256Gcm::new_from_slice(&self.secret[..])
			.map_err(|_| HybridError::FailedToCreateAes256GcmCipher)?
			.decrypt(Nonce::from_slice(&nonce), payload)
			.map(Zeroizing::new)
			.map_err(|_| HybridError::AesGcm256DecryptError)
	}
}

#[cfg(test)]
mod test_asymmetric {
	use super::*;

	fn pair() -> HybridEncryptPair {
		HybridEncryptPair::from_seeds(
			&bytes_os_rng::<DERIVED_SECRET_LEN>(),
			&bytes_os_rng::<DERIVED_SECRET_LEN>(),
			&bytes_os_rng::<DERIVED_SECRET_LEN>(),
		)
	}

	fn tamper(
		serialized_envelope: &[u8],
		edit: impl Fn(&mut Envelope),
	) -> Vec<u8> {
		let mut envelope =
			Envelope::try_from_slice(serialized_envelope).unwrap();
		edit(&mut envelope);
		borsh::to_vec(&envelope).unwrap()
	}

	#[test]
	fn basic_encrypt_decrypt_works() {
		let alice_pair = pair();
		let plaintext = b"rust test message";

		let envelope = alice_pair.public_key().encrypt(plaintext).unwrap();

		assert_eq!(&alice_pair.decrypt(&envelope).unwrap()[..], plaintext);
	}

	#[test]
	fn envelope_has_the_fixed_overhead() {
		let envelope = pair().public_key().encrypt(&[7u8; 100]).unwrap();

		assert_eq!(
			envelope.len(),
			NONCE_LEN
				+ X25519_PUBLIC_LEN
				+ ML_KEM_CIPHERTEXT_LEN
				+ 4 + 100 + 16
		);
	}

	#[test]
	fn wrong_receiver_cannot_decrypt() {
		let envelope = pair().public_key().encrypt(b"message").unwrap();

		assert_eq!(
			pair().decrypt(&envelope).unwrap_err(),
			HybridError::AesGcm256DecryptError
		);
	}

	#[test]
	fn tampered_encrypted_message_fails() {
		let alice_pair = pair();
		let envelope = alice_pair.public_key().encrypt(b"message").unwrap();

		let tampered = tamper(&envelope, |e| e.encrypted_message.push(0));

		assert_eq!(
			alice_pair.decrypt(&tampered).unwrap_err(),
			HybridError::AesGcm256DecryptError
		);
	}

	#[test]
	fn tampered_nonce_fails() {
		let alice_pair = pair();
		let envelope = alice_pair.public_key().encrypt(b"message").unwrap();

		let tampered = tamper(&envelope, |e| e.nonce[0] ^= 1);

		assert_eq!(
			alice_pair.decrypt(&tampered).unwrap_err(),
			HybridError::AesGcm256DecryptError
		);
	}

	#[test]
	fn tampered_ml_kem_ciphertext_fails() {
		let alice_pair = pair();
		let envelope = alice_pair.public_key().encrypt(b"message").unwrap();

		let tampered = tamper(&envelope, |e| e.ml_kem_ciphertext[0] ^= 1);

		assert_eq!(
			alice_pair.decrypt(&tampered).unwrap_err(),
			HybridError::AesGcm256DecryptError
		);
	}

	#[test]
	fn tampered_ephemeral_x25519_key_fails() {
		let alice_pair = pair();
		let envelope = alice_pair.public_key().encrypt(b"message").unwrap();

		let tampered = tamper(&envelope, |e| e.ephemeral_x25519_public[0] ^= 1);

		assert_eq!(
			alice_pair.decrypt(&tampered).unwrap_err(),
			HybridError::AesGcm256DecryptError
		);
	}

	#[test]
	fn low_order_ephemeral_x25519_key_is_rejected() {
		let alice_pair = pair();
		let envelope = alice_pair.public_key().encrypt(b"message").unwrap();

		let tampered =
			tamper(&envelope, |e| e.ephemeral_x25519_public = [0u8; 32]);

		assert_eq!(
			alice_pair.decrypt(&tampered).unwrap_err(),
			HybridError::NonContributoryX25519Exchange
		);
	}

	#[test]
	fn low_order_receiver_x25519_key_is_refused() {
		let mut public = pair().public_key();
		public.x25519_public = [0u8; 32];

		assert_eq!(
			public.encrypt(b"message").unwrap_err(),
			HybridError::NonContributoryX25519Exchange
		);
	}

	#[test]
	fn truncated_envelope_fails_to_deserialize() {
		let alice_pair = pair();
		let envelope = alice_pair.public_key().encrypt(b"message").unwrap();

		assert_eq!(
			alice_pair.decrypt(&envelope[..envelope.len() - 1]).unwrap_err(),
			HybridError::FailedToDeserializeEnvelope
		);
	}

	#[test]
	fn public_key_roundtrip_bytes() {
		let alice_pair = pair();
		let bytes = alice_pair.public_key().to_bytes();

		let public2 = HybridEncryptPublic::from_bytes(&bytes).unwrap();
		let envelope = public2.encrypt(b"message").unwrap();

		assert_eq!(&alice_pair.decrypt(&envelope).unwrap()[..], b"message");
	}

	#[test]
	fn malformed_ml_kem_public_key_is_rejected() {
		let mut bytes = pair().public_key().to_bytes();
		bytes[..ML_KEM_PUBLIC_LEN].fill(0xff);

		assert_eq!(
			HybridEncryptPublic::from_bytes(&bytes).unwrap_err(),
			HybridError::FailedToReadPublicKey
		);
	}
}

#[cfg(test)]
mod test_symmetric {
	use super::*;

	#[test]
	fn encrypt_decrypt_round_trip() {
		let key = AesGcm256Secret::generate();

		let envelope = key.encrypt(b"rust test message").unwrap();

		assert_eq!(&key.decrypt(&envelope).unwrap()[..], b"rust test message");
	}

	#[test]
	fn tampered_payload_errors() {
		let key = AesGcm256Secret::generate();
		let envelope_bytes = key.encrypt(b"rust test message").unwrap();

		let mut envelope =
			SymmetricEnvelope::try_from_slice(&envelope_bytes).unwrap();
		envelope.encrypted_message[0] ^= 1;
		let serialized_envelope = borsh::to_vec(&envelope).unwrap();

		assert_eq!(
			key.decrypt(&serialized_envelope).unwrap_err(),
			HybridError::AesGcm256DecryptError
		);
	}

	#[test]
	fn different_key_cannot_decrypt() {
		let envelope =
			AesGcm256Secret::generate().encrypt(b"rust test message").unwrap();

		assert_eq!(
			AesGcm256Secret::generate().decrypt(&envelope).unwrap_err(),
			HybridError::AesGcm256DecryptError
		);
	}
}
