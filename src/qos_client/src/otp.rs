//! Member keys derived from a `YubiKey` OTP challenge-response slot.
//!
//! A `YubiKey` member's hybrid key is never stored. Its 32-byte master seed is
//! `HKDF-SHA512(salt, response||Argon2id(passphrase, salt), OTP_SEED_INFO)`,
//! where `response` is the device's 20-byte HMAC-SHA1 answer to the challenge
//! `salt`. The salt is public and sits in a file beside the member's public
//! key; the slot secret never leaves the device. Losing the salt file, the
//! device or the passphrase loses the key.
//!
//! The device answers a given salt the same way forever, so one captured
//! response would otherwise rebuild the key for good. The passphrase is what
//! that capture still lacks, the way a PIN guarded a PIV key: an attacker
//! holding a response must still guess the passphrase, at an Argon2id cost per
//! guess.
//!
//! The challenge command runs through `sh -c` with `{challenge}` replaced by
//! the hex salt, so an operator pins a device with
//! `ykman --device <serial> otp calculate 2 {challenge}`. A command that could
//! program, delete or reset the device is refused before it runs.

use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _, path::Path};

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use qos_hybrid::{HybridError, HybridPair, MASTER_SEED_LEN, bytes_os_rng};
use sha2::Sha512;
use zeroize::Zeroizing;

/// The token a challenge command must contain; replaced by the hex salt.
pub const CHALLENGE_PLACEHOLDER: &str = "{challenge}";
/// Challenge command used when none is given: `YubiKey` OTP slot 2.
pub const DEFAULT_CHALLENGE_COMMAND: &str = "ykman otp calculate 2 {challenge}";
/// Length of a member salt.
pub const SALT_LEN: usize = 32;
/// HKDF-SHA512 info string of the member seed derivation.
pub const OTP_SEED_INFO: &[u8] =
	b"qos_hybrid_yubikey_otp_passphrase_member_seed_v1";
/// Length of an HMAC-SHA1 challenge-response answer.
pub const RESPONSE_LEN: usize = 20;
/// Shortest passphrase a new member key accepts.
pub const PASSPHRASE_MIN_LEN: usize = 12;
/// Argon2id memory cost, in KiB (64 MiB, RFC 9106's second recommendation).
pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
/// Argon2id passes over memory.
pub const ARGON2_ITERATIONS: u32 = 3;
/// Argon2id lanes.
pub const ARGON2_LANES: u32 = 1;
/// Length of the Argon2id passphrase key.
const PASSPHRASE_KEY_LEN: usize = 32;

const DESTRUCTIVE_DEVICE_COMMANDS: &[&str] = &[
	"reset",
	"otp chalresp",
	"otp delete",
	"otp swap",
	"otp static",
	"otp yubiotp",
	"otp hotp",
	"otp settings",
	"otp ndef",
	"otp access",
	"piv keys generate",
	"piv keys import",
	"piv keys delete",
	"piv certificates",
	"piv access",
	"config",
	"yubikey-piv-reset",
	"ykpersonalize",
];

/// Errors deriving a member key from a challenge-response device.
#[derive(Debug)]
pub enum OtpError {
	/// The command has no `{challenge}`, so every salt would get the same
	/// answer and the key would derive from the salt file alone.
	CommandMissingChallenge,
	/// The command contains a fragment that writes to or resets the device,
	/// which would destroy the secret every member key derives from.
	CommandDestructive(&'static str),
	/// The command could not run or exited non-zero.
	CommandFailed(String),
	/// The command did not print hex.
	ResponseNotHex(String),
	/// The command printed nothing.
	ResponseEmpty,
	/// The command's answer is not a 20-byte HMAC-SHA1 response.
	ResponseWrongLength(usize),
	/// A new member key's passphrase is shorter than
	/// [`PASSPHRASE_MIN_LEN`].
	PassphraseTooShort,
	/// Argon2id refused its parameters or input.
	Argon2(String),
	/// Two different challenges got the same answer, so the device never saw
	/// the salt.
	ChallengeIgnored,
	/// One challenge got two different answers, so the key could never be
	/// derived again.
	ResponseUnstable,
	/// The salt file could not be read or written, or is malformed.
	SaltFile(String),
	/// Building the hybrid pair failed.
	Hybrid(HybridError),
}

impl From<HybridError> for OtpError {
	fn from(err: HybridError) -> Self {
		Self::Hybrid(err)
	}
}

/// Generate a fresh member salt.
#[must_use]
pub fn fresh_salt() -> [u8; SALT_LEN] {
	*bytes_os_rng::<SALT_LEN>()
}

/// Check that `command` answers a challenge and cannot write to the device.
///
/// # Errors
///
/// Returns [`OtpError::CommandMissingChallenge`] or
/// [`OtpError::CommandDestructive`].
pub fn validate_command(command: &str) -> Result<(), OtpError> {
	if !command.contains(CHALLENGE_PLACEHOLDER) {
		return Err(OtpError::CommandMissingChallenge);
	}
	if let Some(fragment) = destructive_fragment(command) {
		return Err(OtpError::CommandDestructive(fragment));
	}
	Ok(())
}

fn destructive_fragment(command: &str) -> Option<&'static str> {
	let lowered = command.to_lowercase();
	let tokens: Vec<&str> = lowered
		.split(|c: char| {
			c.is_whitespace()
				|| matches!(c, ';' | '&' | '|' | '(' | ')' | '`' | '"' | '\'')
		})
		.filter(|token| !token.is_empty())
		.collect();
	DESTRUCTIVE_DEVICE_COMMANDS.iter().copied().find(|fragment| {
		let wanted: Vec<&str> = fragment.split_whitespace().collect();
		tokens.windows(wanted.len()).any(|window| window == wanted.as_slice())
	})
}

fn respond(
	command: &str,
	challenge: &[u8],
) -> Result<Zeroizing<Vec<u8>>, OtpError> {
	validate_command(command)?;

	eprintln!(
		"Waiting for the challenge-response device. On a YubiKey, slot 2 \
		 answers a LONG press of about three seconds; a short press fires \
		 slot 1, which types its one-time password wherever the cursor is."
	);
	let rendered =
		command.replace(CHALLENGE_PLACEHOLDER, &qos_hex::encode(challenge));
	let output = std::process::Command::new("sh")
		.arg("-c")
		.arg(&rendered)
		.output()
		.map_err(|e| OtpError::CommandFailed(e.to_string()))?;
	let stdout = Zeroizing::new(output.stdout);
	if !output.status.success() {
		return Err(OtpError::CommandFailed(format!(
			"exit {}: {}",
			output.status,
			String::from_utf8_lossy(&output.stderr).trim()
		)));
	}

	let text =
		Zeroizing::new(String::from_utf8_lossy(&stdout).trim().to_owned());
	if text.is_empty() {
		return Err(OtpError::ResponseEmpty);
	}
	let response = qos_hex::decode(&text)
		.map(Zeroizing::new)
		.map_err(|e| OtpError::ResponseNotHex(format!("{e:?}")))?;
	if response.len() != RESPONSE_LEN {
		return Err(OtpError::ResponseWrongLength(response.len()));
	}
	Ok(response)
}

fn passphrase_key(
	passphrase: &[u8],
	salt: &[u8],
) -> Result<Zeroizing<[u8; PASSPHRASE_KEY_LEN]>, OtpError> {
	let params = Params::new(
		ARGON2_MEMORY_KIB,
		ARGON2_ITERATIONS,
		ARGON2_LANES,
		Some(PASSPHRASE_KEY_LEN),
	)
	.map_err(|e| OtpError::Argon2(e.to_string()))?;
	let mut key = Zeroizing::new([0u8; PASSPHRASE_KEY_LEN]);
	Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
		.hash_password_into(passphrase, salt, &mut *key)
		.map_err(|e| OtpError::Argon2(e.to_string()))?;
	Ok(key)
}

fn pair_from_response(
	response: &[u8],
	salt: &[u8],
	passphrase: &[u8],
) -> Result<HybridPair, OtpError> {
	let passphrase_key = passphrase_key(passphrase, salt)?;
	let mut input_key =
		Zeroizing::new(Vec::with_capacity(response.len() + PASSPHRASE_KEY_LEN));
	input_key.extend_from_slice(response);
	input_key.extend_from_slice(&*passphrase_key);

	let mut seed = Zeroizing::new([0u8; MASTER_SEED_LEN]);
	Hkdf::<Sha512>::new(Some(salt), &input_key)
		.expand(OTP_SEED_INFO, &mut *seed)
		.map_err(|_| HybridError::HkdfExpansionFailed)?;
	HybridPair::from_master_seed(&seed).map_err(Into::into)
}

/// Derive the member pair for `salt` and `passphrase` from one device
/// response.
///
/// # Errors
///
/// Returns [`OtpError`] if the command is refused or fails, or the pair
/// cannot be built.
pub fn derive_member_pair(
	command: &str,
	salt: &[u8],
	passphrase: &[u8],
) -> Result<HybridPair, OtpError> {
	pair_from_response(&respond(command, salt)?, salt, passphrase)
}

/// Derive the member pair for `salt`, first proving the device answers the
/// challenge and answers it the same way twice. Use when minting a key, where
/// a bad command would otherwise register a key nobody can derive again.
///
/// # Errors
///
/// Returns [`OtpError::PassphraseTooShort`] for a passphrase under
/// [`PASSPHRASE_MIN_LEN`], [`OtpError::ChallengeIgnored`] or
/// [`OtpError::ResponseUnstable`] for a command that would not reproduce the
/// key, and [`OtpError`] for any other failure.
pub fn derive_member_pair_probed(
	command: &str,
	salt: &[u8],
	passphrase: &[u8],
) -> Result<HybridPair, OtpError> {
	if passphrase.len() < PASSPHRASE_MIN_LEN {
		return Err(OtpError::PassphraseTooShort);
	}
	let mut probe = fresh_salt();
	if probe.as_slice() == salt {
		probe[0] ^= 1;
	}

	let first = respond(command, salt)?;
	if *respond(command, &probe)? == *first {
		return Err(OtpError::ChallengeIgnored);
	}
	if *respond(command, salt)? != *first {
		return Err(OtpError::ResponseUnstable);
	}

	pair_from_response(&first, salt, passphrase)
}

/// Read a hex member salt from `path`.
///
/// # Errors
///
/// Returns [`OtpError::SaltFile`] if the file is missing, not hex, or not
/// [`SALT_LEN`] bytes.
pub fn read_salt<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, OtpError> {
	let path = path.as_ref();
	let text = std::fs::read_to_string(path).map_err(|e| {
		OtpError::SaltFile(format!("failed to read {}: {e}", path.display()))
	})?;
	let salt = qos_hex::decode(text.trim()).map_err(|e| {
		OtpError::SaltFile(format!("{} is not hex: {e:?}", path.display()))
	})?;
	if salt.len() != SALT_LEN {
		return Err(OtpError::SaltFile(format!(
			"{} holds {} bytes, expected {SALT_LEN}",
			path.display(),
			salt.len()
		)));
	}
	Ok(salt)
}

/// Write `salt` as hex to a new file at `path`, refusing to replace one: an
/// existing salt may be the only way to derive a registered member key.
///
/// # Errors
///
/// Returns [`OtpError::SaltFile`] if the file exists or cannot be written.
pub fn write_new_salt<P: AsRef<Path>>(
	path: P,
	salt: &[u8],
) -> Result<(), OtpError> {
	let path = path.as_ref();
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o644)
		.open(path)
		.map_err(|e| {
			OtpError::SaltFile(format!(
				"refusing to create {}: {e}; an existing salt may be the only \
				 way to derive a registered member key",
				path.display()
			))
		})?;
	file.write_all(qos_hex::encode(salt).as_bytes()).map_err(|e| {
		OtpError::SaltFile(format!("failed to write {}: {e}", path.display()))
	})
}

#[cfg(test)]
mod test {
	use qos_test_primitives::PathWrapper;

	use super::*;

	const ECHO_COMMAND: &str = "printf '%s' {challenge} | cut -c1-40";
	const PASSPHRASE: &[u8] = b"correct horse battery";

	#[test]
	fn same_salt_derives_the_same_pair() {
		let salt = fresh_salt();

		let first =
			derive_member_pair(ECHO_COMMAND, &salt, PASSPHRASE).unwrap();
		let second =
			derive_member_pair_probed(ECHO_COMMAND, &salt, PASSPHRASE).unwrap();

		assert!(first.public_key() == second.public_key());
	}

	#[test]
	fn a_captured_response_without_the_passphrase_derives_another_key() {
		let salt = fresh_salt();

		let member =
			derive_member_pair(ECHO_COMMAND, &salt, PASSPHRASE).unwrap();
		let guess =
			derive_member_pair(ECHO_COMMAND, &salt, b"wrong passphrase!")
				.unwrap();

		assert!(
			member.public_key() != guess.public_key(),
			"the device response alone must not rebuild the member key"
		);
	}

	#[test]
	fn probe_rejects_a_short_passphrase() {
		assert!(matches!(
			derive_member_pair_probed(
				ECHO_COMMAND,
				&fresh_salt(),
				b"too short"
			),
			Err(OtpError::PassphraseTooShort)
		));
	}

	#[test]
	fn response_that_is_not_hmac_sha1_length_is_refused() {
		assert!(matches!(
			derive_member_pair(
				"printf '%s' {challenge}",
				&fresh_salt(),
				PASSPHRASE
			),
			Err(OtpError::ResponseWrongLength(32))
		));
	}

	#[test]
	fn different_salts_derive_different_pairs() {
		let first = derive_member_pair(ECHO_COMMAND, &fresh_salt(), PASSPHRASE)
			.unwrap();
		let second =
			derive_member_pair(ECHO_COMMAND, &fresh_salt(), PASSPHRASE)
				.unwrap();

		assert!(first.public_key() != second.public_key());
	}

	#[test]
	fn command_without_placeholder_is_refused() {
		assert!(matches!(
			derive_member_pair("echo 00", &fresh_salt(), PASSPHRASE),
			Err(OtpError::CommandMissingChallenge)
		));
	}

	#[test]
	fn destructive_command_is_refused() {
		assert!(matches!(
			validate_command("ykman otp chalresp --generate 2 {challenge}"),
			Err(OtpError::CommandDestructive("otp chalresp"))
		));
		assert!(matches!(
			validate_command(
				"ykman otp calculate 2 {challenge}; ykman otp delete 2"
			),
			Err(OtpError::CommandDestructive("otp delete"))
		));
		assert!(validate_command(DEFAULT_CHALLENGE_COMMAND).is_ok());
	}

	#[test]
	fn probe_rejects_a_command_that_ignores_the_challenge() {
		assert!(matches!(
			derive_member_pair_probed(
				"printf '%040d' 0 # {challenge}",
				&fresh_salt(),
				PASSPHRASE
			),
			Err(OtpError::ChallengeIgnored)
		));
	}

	#[test]
	fn probe_rejects_an_unstable_command() {
		let unstable =
			"od -An -N20 -tx1 /dev/urandom | tr -d ' \\n' # {challenge}";

		assert!(matches!(
			derive_member_pair_probed(unstable, &fresh_salt(), PASSPHRASE),
			Err(OtpError::ResponseUnstable)
		));
	}

	#[test]
	fn salt_file_round_trips_and_is_never_replaced() {
		let path =
			PathWrapper::from("/tmp/qos_client_otp_salt_round_trip.salt");
		let salt = fresh_salt();

		write_new_salt(&*path, &salt).unwrap();
		assert_eq!(read_salt(&*path).unwrap(), salt);
		assert!(matches!(
			write_new_salt(&*path, &fresh_salt()),
			Err(OtpError::SaltFile(_))
		));
		assert_eq!(read_salt(&*path).unwrap(), salt);
	}
}
