#![doc = include_str!("../README.md")]

use std::path::Path;

use hkdf::Hkdf;
use rand_core::{OsRng, TryRngCore};
use sha2::{Digest, Sha512};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
	encrypt::{AesGcm256Secret, HybridEncryptPair, HybridEncryptPublic},
	sign::{MlDsaSignPair, MlDsaSignPublic},
};

pub mod encrypt;
pub mod sign;

/// Master seed derive path for the ML-KEM-1024 `d` seed.
pub const ML_KEM_D_DERIVE_PATH: &[u8] = b"qos_hybrid_ml_kem_1024_d";
/// Master seed derive path for the ML-KEM-1024 `z` seed.
pub const ML_KEM_Z_DERIVE_PATH: &[u8] = b"qos_hybrid_ml_kem_1024_z";
/// Master seed derive path for the X25519 secret.
pub const X25519_DERIVE_PATH: &[u8] = b"qos_hybrid_x25519";
/// Master seed derive path for the ML-DSA-87 `xi` seed.
pub const ML_DSA_XI_DERIVE_PATH: &[u8] = b"qos_hybrid_ml_dsa_87_xi";
/// Master seed derive path for the AES-256-GCM secret.
pub const AES_GCM_256_PATH: &[u8] = b"qos_hybrid_aes_gcm_256";
/// Domain prefix of [`HybridPublic::attestation_binding`].
pub const ATTESTATION_BINDING_DOMAIN: &[u8] =
	b"qos_hybrid_attestation_binding_v1";
/// Length of each secret derived from the master seed.
pub const DERIVED_SECRET_LEN: usize = 32;
/// Length of the master seed.
pub const MASTER_SEED_LEN: usize = 32;
/// Length of an ML-KEM-1024 encapsulation key.
pub const ML_KEM_PUBLIC_LEN: usize = fips203::ml_kem_1024::EK_LEN;
/// Length of an ML-KEM-1024 ciphertext.
pub const ML_KEM_CIPHERTEXT_LEN: usize = fips203::ml_kem_1024::CT_LEN;
/// Length of an X25519 public key.
pub const X25519_PUBLIC_LEN: usize = 32;
/// Length of the encryption half of a [`HybridPublic`].
pub const ENCRYPT_PUBLIC_LEN: usize = ML_KEM_PUBLIC_LEN + X25519_PUBLIC_LEN;
/// Length of an ML-DSA-87 public key.
pub const SIGN_PUBLIC_LEN: usize = fips204::ml_dsa_87::PK_LEN;
/// Length of an ML-DSA-87 signature.
pub const SIGNATURE_LEN: usize = fips204::ml_dsa_87::SIG_LEN;
/// Length of a serialized [`HybridPublic`].
pub const PUBLIC_KEY_LEN: usize = ENCRYPT_PUBLIC_LEN + SIGN_PUBLIC_LEN;
/// Length of [`HybridPublic::attestation_binding`].
pub const ATTESTATION_BINDING_LEN: usize = 64;

/// Errors for qos hybrid keys.
#[derive(
	Debug,
	Clone,
	PartialEq,
	Eq,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
pub enum HybridError {
	/// Hex encoding error.
	QosHex(String),
	/// IO error
	IOError(String),
	/// The encryption envelope could not be serialized. This is likely a bug
	/// with the code.
	FailedToSerializeEnvelope,
	/// The encryption envelope could not be deserialized.
	FailedToDeserializeEnvelope,
	/// An error while decrypting the ciphertext with the `AesGcm256` cipher.
	AesGcm256DecryptError,
	/// An error while encrypting the plaintext with the `AesGcm256` cipher.
	AesGcm256EncryptError,
	/// Failed to create the `AesGcm256` cipher.
	FailedToCreateAes256GcmCipher,
	/// ML-KEM-1024 decapsulation refused the ciphertext.
	MlKemDecapsulationFailed,
	/// The X25519 exchange produced the all-zero secret: the peer sent a
	/// low-order point.
	NonContributoryX25519Exchange,
	/// Signature could not be de-serialized.
	FailedToDeserializeSignature,
	/// The signature could not be verified against the given message and
	/// public key.
	FailedSignatureVerification,
	/// ML-DSA-87 signing failed.
	SigningFailed,
	/// The raw bytes could not be interpreted as a public key.
	FailedToReadPublicKey,
	/// The public key is too long to be valid.
	EncodedPublicKeyTooLong,
	/// The public key is too short to be valid.
	EncodedPublicKeyTooShort,
	/// Error'ed while running HKDF expansion
	HkdfExpansionFailed,
	/// Master seed was not stored as valid utf8 encoding.
	MasterSeedInvalidUtf8,
	/// Master seed was not the correct length.
	MasterSeedInvalidLength,
	/// Master seed file contents were invalid.
	InvalidMasterSeed,
}

impl From<qos_hex::HexError> for HybridError {
	fn from(err: qos_hex::HexError) -> Self {
		match err {
			qos_hex::HexError::InvalidUtf8(_) => {
				HybridError::MasterSeedInvalidUtf8
			}
			err => Self::QosHex(format!("{err:?}")),
		}
	}
}

/// Derive a secret from a master seed with HKDF-SHA512, salted with
/// `derive_path`.
///
/// # Errors
///
/// Returns [`HybridError::HkdfExpansionFailed`] if HKDF expansion fails.
pub fn derive_secret(
	seed: &Zeroizing<[u8; MASTER_SEED_LEN]>,
	derive_path: &[u8],
) -> Result<Zeroizing<[u8; DERIVED_SECRET_LEN]>, HybridError> {
	let hk = Hkdf::<Sha512>::new(Some(derive_path), &seed[..]);

	let mut buf = Zeroizing::new([0u8; DERIVED_SECRET_LEN]);
	hk.expand(&[], &mut *buf).map_err(|_| HybridError::HkdfExpansionFailed)?;

	Ok(buf)
}

fn write_owner_only(path: &Path, buf: &[u8]) -> std::io::Result<()> {
	use std::{
		io::Write as _,
		os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
	};

	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create(true)
		.truncate(true)
		.mode(0o600)
		.open(path)?;
	file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
	file.write_all(buf)
}

/// Generate an `N` length byte buffer from the OS randomness source.
///
/// # Panics
///
/// Panics if the OS randomness source fails, since no key or nonce may be
/// produced without it.
#[must_use]
pub fn bytes_os_rng<const N: usize>() -> Zeroizing<[u8; N]> {
	let mut buf = Zeroizing::new([0u8; N]);
	OsRng.try_fill_bytes(&mut *buf).expect(
		"the OS randomness source must be available to make keys and nonces",
	);

	buf
}

/// Hybrid private key pair for signing and encryption, every part derived
/// from one master seed.
#[derive(ZeroizeOnDrop)]
pub struct HybridPair {
	encrypt_private: HybridEncryptPair,
	sign_private: MlDsaSignPair,
	master_seed: Zeroizing<[u8; MASTER_SEED_LEN]>,
	aes_gcm_256_secret: AesGcm256Secret,
}

#[cfg(any(feature = "mock", test))]
impl Clone for HybridPair {
	fn clone(&self) -> Self {
		Self::from_master_seed(&self.master_seed)
			.expect("a seed that built a pair builds it again")
	}
}

#[cfg(any(feature = "mock", test))]
impl PartialEq for HybridPair {
	fn eq(&self, other: &Self) -> bool {
		self.master_seed == other.master_seed
	}
}

#[cfg(any(feature = "mock", test))]
impl Eq for HybridPair {}

impl HybridPair {
	/// Generate a new pair from a fresh master seed.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if key derivation fails.
	pub fn generate() -> Result<Self, HybridError> {
		Self::from_master_seed(&bytes_os_rng::<MASTER_SEED_LEN>())
	}

	/// Create `Self` from a master seed.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if key derivation fails.
	pub fn from_master_seed(
		master_seed: &Zeroizing<[u8; MASTER_SEED_LEN]>,
	) -> Result<Self, HybridError> {
		let ml_kem_d = derive_secret(master_seed, ML_KEM_D_DERIVE_PATH)?;
		let ml_kem_z = derive_secret(master_seed, ML_KEM_Z_DERIVE_PATH)?;
		let x25519 = derive_secret(master_seed, X25519_DERIVE_PATH)?;
		let ml_dsa_xi = derive_secret(master_seed, ML_DSA_XI_DERIVE_PATH)?;
		let aes_gcm_256 = derive_secret(master_seed, AES_GCM_256_PATH)?;

		Ok(Self {
			encrypt_private: HybridEncryptPair::from_seeds(
				&ml_kem_d, &ml_kem_z, &x25519,
			),
			sign_private: MlDsaSignPair::from_seed(&ml_dsa_xi),
			master_seed: master_seed.clone(),
			aes_gcm_256_secret: AesGcm256Secret::from_bytes(*aes_gcm_256),
		})
	}

	/// Encrypt the given `msg` with the symmetric encryption secret.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if encryption fails.
	pub fn aes_gcm_256_encrypt(
		&self,
		msg: &[u8],
	) -> Result<Vec<u8>, HybridError> {
		self.aes_gcm_256_secret.encrypt(msg)
	}

	/// Decrypt a message with the symmetric encryption secret.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if decryption or envelope deserialization fails.
	pub fn aes_gcm_256_decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Zeroizing<Vec<u8>>, HybridError> {
		self.aes_gcm_256_secret.decrypt(serialized_envelope)
	}

	/// Decrypt a message encrypted to this pair's public key.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if decryption or envelope deserialization fails.
	pub fn decrypt(
		&self,
		serialized_envelope: &[u8],
	) -> Result<Zeroizing<Vec<u8>>, HybridError> {
		self.encrypt_private.decrypt(serialized_envelope)
	}

	/// Sign the message with ML-DSA-87 and return the raw signature.
	///
	/// # Errors
	///
	/// Returns [`HybridError::SigningFailed`] if signing fails.
	pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HybridError> {
		self.sign_private.sign(message)
	}

	/// Get the public key.
	#[must_use]
	pub fn public_key(&self) -> HybridPublic {
		HybridPublic {
			encrypt_public: self.encrypt_private.public_key(),
			sign_public: self.sign_private.public_key(),
		}
	}

	/// Get the raw master seed used to create this pair.
	/// CAUTION: this is secret material and should be used with care.
	#[must_use]
	pub fn to_master_seed(&self) -> &Zeroizing<[u8; MASTER_SEED_LEN]> {
		&self.master_seed
	}

	/// Convert the master seed to hex bytes.
	/// CAUTION: this is secret material and should be used with care.
	#[must_use]
	pub fn to_master_seed_hex(&self) -> Zeroizing<Vec<u8>> {
		Zeroizing::new(qos_hex::encode_to_vec(&self.master_seed[..]))
	}

	/// Write the raw master seed to file as hex encoded, owner-only.
	///
	/// # Errors
	///
	/// Returns [`HybridError::IOError`] if the file cannot be written.
	pub fn to_hex_file<P: AsRef<Path>>(
		&self,
		path: P,
	) -> Result<(), HybridError> {
		let hex_string = Zeroizing::new(qos_hex::encode(&self.master_seed[..]));
		write_owner_only(path.as_ref(), hex_string.as_bytes()).map_err(|e| {
			HybridError::IOError(format!(
				"failed to write master secret to {}: {e}",
				path.as_ref().display()
			))
		})
	}

	/// Read the raw, hex encoded master seed from a file.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if the file cannot be read, the hex is invalid,
	/// or the seed length is wrong.
	pub fn from_hex_file<P: AsRef<Path>>(path: P) -> Result<Self, HybridError> {
		let hex_bytes = Zeroizing::new(std::fs::read(&path).map_err(|e| {
			HybridError::IOError(format!(
				"failed to read master seed from {}: {e}",
				path.as_ref().display()
			))
		})?);

		let hex_str = std::str::from_utf8(&hex_bytes)
			.map_err(|_| HybridError::InvalidMasterSeed)?;
		let mut master_seed = Zeroizing::new([0u8; MASTER_SEED_LEN]);
		qos_hex::decode_to_buf(hex_str.trim(), &mut *master_seed)
			.map_err(|_| HybridError::InvalidMasterSeed)?;
		Self::from_master_seed(&master_seed)
	}

	/// Get a reference to the underlying AES-GCM-256 secret.
	///
	/// CAUTION: this is secret material and should be used with care.
	#[must_use]
	pub fn aes_gcm_256_secret(&self) -> &Zeroizing<[u8; 32]> {
		self.aes_gcm_256_secret.to_bytes()
	}
}

/// Hybrid public key: an ML-KEM-1024 + X25519 encryption key and an
/// ML-DSA-87 verifying key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublic {
	encrypt_public: HybridEncryptPublic,
	sign_public: MlDsaSignPublic,
}

impl HybridPublic {
	/// Encrypt a message to this public key.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if encryption fails.
	pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, HybridError> {
		self.encrypt_public.encrypt(message)
	}

	/// Verify an ML-DSA-87 `signature` over `message` against this key.
	///
	/// # Errors
	///
	/// Returns [`HybridError::FailedSignatureVerification`] if the signature
	/// is invalid.
	pub fn verify(
		&self,
		message: &[u8],
		signature: &[u8],
	) -> Result<(), HybridError> {
		self.sign_public.verify(message, signature)
	}

	/// Serialize as `ml_kem_public||x25519_public||ml_dsa_public`.
	#[must_use]
	pub fn to_bytes(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(PUBLIC_KEY_LEN);
		bytes.extend_from_slice(&self.encrypt_public.to_bytes());
		bytes.extend_from_slice(&self.sign_public.to_bytes());
		bytes
	}

	/// Serialize the encryption half, `ml_kem_public||x25519_public`.
	#[must_use]
	pub fn encryption_public_key_bytes(&self) -> Box<[u8]> {
		self.encrypt_public.to_bytes().into_boxed_slice()
	}

	/// Serialize the ML-DSA-87 verifying key.
	#[must_use]
	pub fn signing_public_key_bytes(&self) -> Box<[u8]> {
		self.sign_public.to_bytes().into_boxed_slice()
	}

	/// The 64-byte digest that stands for this key where the full key does
	/// not fit: a Nitro attestation document's `public_key` field and the
	/// manifest PCR commitments. It is
	/// `SHA512(ATTESTATION_BINDING_DOMAIN||to_bytes())`.
	#[must_use]
	pub fn attestation_binding(&self) -> [u8; ATTESTATION_BINDING_LEN] {
		let mut hasher = Sha512::new();
		hasher.update(ATTESTATION_BINDING_DOMAIN);
		hasher.update(self.to_bytes());
		hasher.finalize().into()
	}

	/// Deserialize from `ml_kem_public||x25519_public||ml_dsa_public`.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if the bytes are the wrong length or a part is
	/// not a valid key.
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
		if bytes.len() > PUBLIC_KEY_LEN {
			return Err(HybridError::EncodedPublicKeyTooLong);
		}
		if bytes.len() < PUBLIC_KEY_LEN {
			return Err(HybridError::EncodedPublicKeyTooShort);
		}

		let (encrypt_bytes, sign_bytes) = bytes.split_at(ENCRYPT_PUBLIC_LEN);

		Ok(Self {
			encrypt_public: HybridEncryptPublic::from_bytes(encrypt_bytes)?,
			sign_public: MlDsaSignPublic::from_bytes(sign_bytes)?,
		})
	}

	/// Convert to hex bytes.
	#[must_use]
	pub fn to_hex_bytes(&self) -> Vec<u8> {
		qos_hex::encode_to_vec(&self.to_bytes())
	}

	/// Write the public key to a file encoded as a hex string.
	///
	/// # Errors
	///
	/// Returns [`HybridError::IOError`] if the file cannot be written.
	pub fn to_hex_file<P: AsRef<Path>>(
		&self,
		path: P,
	) -> Result<(), HybridError> {
		let hex_string = qos_hex::encode(&self.to_bytes());
		std::fs::write(&path, hex_string.as_bytes()).map_err(|e| {
			HybridError::IOError(format!(
				"failed to write public key bytes to {}: {e}",
				path.as_ref().display()
			))
		})
	}

	/// Read the hex encoded public key from a file.
	///
	/// # Errors
	///
	/// Returns [`HybridError`] if the file cannot be read, the hex is invalid,
	/// or the bytes are not a valid public key.
	pub fn from_hex_file<P: AsRef<Path>>(path: P) -> Result<Self, HybridError> {
		let hex_bytes = std::fs::read(&path).map_err(|e| {
			HybridError::IOError(format!(
				"failed to read public key bytes from {}: {e}",
				path.as_ref().display()
			))
		})?;

		let public_key_bytes =
			qos_hex::decode_from_vec(hex_bytes).map_err(HybridError::from)?;

		Self::from_bytes(&public_key_bytes)
	}
}

#[cfg(test)]
mod test {
	use qos_test_primitives::PathWrapper;

	use super::*;

	#[test]
	fn public_key_component_bytes_match_combined_encoding() {
		let public_key = HybridPair::generate().unwrap().public_key();
		let component_bytes: Vec<_> = public_key
			.encryption_public_key_bytes()
			.iter()
			.chain(public_key.signing_public_key_bytes().iter())
			.copied()
			.collect();

		assert_eq!(component_bytes, public_key.to_bytes());
		assert_eq!(component_bytes.len(), PUBLIC_KEY_LEN);
	}

	#[test]
	fn sign_and_verification_works() {
		let message = b"a message to authenticate";

		let pair = HybridPair::generate().unwrap();
		let signature = pair.sign(message).unwrap();

		assert_eq!(signature.len(), SIGNATURE_LEN);
		assert!(pair.public_key().verify(message, &signature).is_ok());
	}

	#[test]
	fn verification_rejects_wrong_signer() {
		let message = b"a message to authenticate";

		let alice_pair = HybridPair::generate().unwrap();
		let signature = alice_pair.sign(message).unwrap();

		let bob_public = HybridPair::generate().unwrap().public_key();

		assert_eq!(
			bob_public.verify(message, &signature).unwrap_err(),
			HybridError::FailedSignatureVerification
		);
	}

	#[test]
	fn verification_rejects_wrong_message() {
		let pair = HybridPair::generate().unwrap();
		let signature = pair.sign(b"signed").unwrap();

		assert_eq!(
			pair.public_key().verify(b"not signed", &signature).unwrap_err(),
			HybridError::FailedSignatureVerification
		);
	}

	#[test]
	fn basic_encrypt_decrypt_works() {
		let alice_pair = HybridPair::generate().unwrap();
		let plaintext = b"rust test message";

		let serialized_envelope =
			alice_pair.public_key().encrypt(plaintext).unwrap();

		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();
		assert_eq!(&decrypted[..], plaintext);
	}

	#[test]
	fn wrong_receiver_cannot_decrypt() {
		let alice_pair = HybridPair::generate().unwrap();
		let plaintext = b"rust test message";

		let serialized_envelope =
			alice_pair.public_key().encrypt(plaintext).unwrap();

		let bob_pair = HybridPair::generate().unwrap();

		assert_eq!(
			bob_pair.decrypt(&serialized_envelope).unwrap_err(),
			HybridError::AesGcm256DecryptError
		);
	}

	#[test]
	fn public_key_bytes_roundtrip() {
		let alice_pair = HybridPair::generate().unwrap();
		let alice_public_bytes = alice_pair.public_key().to_bytes();

		let alice_public2 =
			HybridPublic::from_bytes(&alice_public_bytes).unwrap();
		assert!(alice_public2 == alice_pair.public_key());

		let plaintext = b"rust test message";
		let serialized_envelope = alice_public2.encrypt(plaintext).unwrap();
		let decrypted = alice_pair.decrypt(&serialized_envelope).unwrap();
		assert_eq!(&decrypted[..], plaintext);

		let message = b"a message to authenticate";
		let signature = alice_pair.sign(message).unwrap();
		assert!(alice_public2.verify(message, &signature).is_ok());
	}

	#[test]
	fn public_key_length_is_checked() {
		let bytes = HybridPair::generate().unwrap().public_key().to_bytes();

		assert_eq!(
			HybridPublic::from_bytes(&bytes[1..]).unwrap_err(),
			HybridError::EncodedPublicKeyTooShort
		);
		let mut too_long = bytes.clone();
		too_long.push(0);
		assert_eq!(
			HybridPublic::from_bytes(&too_long).unwrap_err(),
			HybridError::EncodedPublicKeyTooLong
		);
	}

	#[test]
	fn public_key_to_file_roundtrip() {
		let path =
			PathWrapper::from("/tmp/hybrid_public_key_to_file_roundtrip.pub");
		let alice_pair = HybridPair::generate().unwrap();
		alice_pair.public_key().to_hex_file(&*path).unwrap();

		let alice_public2 = HybridPublic::from_hex_file(&*path).unwrap();

		assert!(alice_public2 == alice_pair.public_key());
	}

	#[test]
	fn master_seed_derives_the_same_pair() {
		let alice_pair = HybridPair::generate().unwrap();
		let public_key = alice_pair.public_key();

		let alice_pair2 =
			HybridPair::from_master_seed(alice_pair.to_master_seed()).unwrap();
		assert!(alice_pair2.public_key() == public_key);

		let plaintext = b"rust test message";
		let serialized_envelope = public_key.encrypt(plaintext).unwrap();
		let decrypted = alice_pair2.decrypt(&serialized_envelope).unwrap();
		assert_eq!(&decrypted[..], plaintext);

		let message = b"a message to authenticate";
		let signature = alice_pair2.sign(message).unwrap();
		assert!(public_key.verify(message, &signature).is_ok());
	}

	#[test]
	fn attestation_binding_commits_to_the_whole_key() {
		let alice = HybridPair::generate().unwrap().public_key();
		let bob = HybridPair::generate().unwrap().public_key();

		assert_eq!(alice.attestation_binding().len(), ATTESTATION_BINDING_LEN);
		assert_eq!(alice.attestation_binding(), alice.attestation_binding());
		assert_ne!(alice.attestation_binding(), bob.attestation_binding());
	}

	#[test]
	fn master_seed_to_file_is_owner_only() {
		use std::os::unix::fs::PermissionsExt as _;

		let path = PathWrapper::from(
			std::env::temp_dir().join("qos_hybrid_seed_mode.secret"),
		);
		std::fs::write(&*path, b"stale").unwrap();
		std::fs::set_permissions(
			&*path,
			std::fs::Permissions::from_mode(0o644),
		)
		.unwrap();

		let pair = HybridPair::generate().unwrap();
		pair.to_hex_file(&*path).unwrap();

		let mode =
			std::fs::metadata(&*path).unwrap().permissions().mode() & 0o777;
		assert_eq!(mode, 0o600);

		let pair2 = HybridPair::from_hex_file(&*path).unwrap();
		assert_eq!(pair.to_master_seed(), pair2.to_master_seed());
	}

	#[test]
	fn from_hex_file_returns_opaque_error_for_invalid_master_seed() {
		let path = PathWrapper::from(
			"/tmp/qos_hybrid_from_hex_file_invalid_master_seed.secret",
		);
		std::fs::write(&*path, b"not a valid seed").unwrap();

		assert!(matches!(
			HybridPair::from_hex_file(&*path),
			Err(HybridError::InvalidMasterSeed)
		));
	}

	#[test]
	fn aes_gcm_256_round_trip_and_key_separation() {
		let plaintext = b"rust test message";
		let key = HybridPair::generate().unwrap();
		let other_key = HybridPair::generate().unwrap();

		let envelope = key.aes_gcm_256_encrypt(plaintext).unwrap();
		assert_eq!(&key.aes_gcm_256_decrypt(&envelope).unwrap()[..], plaintext);
		assert_eq!(
			other_key.aes_gcm_256_decrypt(&envelope).unwrap_err(),
			HybridError::AesGcm256DecryptError
		);
	}
}
