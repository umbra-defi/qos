//! Member keys derived from a `YubiKey` OTP challenge-response slot.
//!
//! A `YubiKey` member's hybrid key is never stored. Its 32-byte master seed is
//! `HKDF-SHA512(salt, response, OTP_SEED_INFO)`, where `response` is the
//! device's HMAC-SHA1 answer to the challenge `salt`. The salt is public and
//! sits in a file beside the member's public key; the slot secret never leaves
//! the device. Losing either the salt file or the device loses the key.
//!
//! The challenge command runs through `sh -c` with `{challenge}` replaced by
//! the hex salt, so an operator pins a device with
//! `ykman --device <serial> otp calculate 2 {challenge}`. A command that could
//! program, delete or reset the device is refused before it runs.

use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _, path::Path};

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
pub const OTP_SEED_INFO: &[u8] = b"qos_hybrid_yubikey_otp_member_seed_v1";

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
	if !output.status.success() {
		return Err(OtpError::CommandFailed(format!(
			"exit {}: {}",
			output.status,
			String::from_utf8_lossy(&output.stderr).trim()
		)));
	}

	let text = Zeroizing::new(
		String::from_utf8_lossy(&output.stdout).trim().to_owned(),
	);
	if text.is_empty() {
		return Err(OtpError::ResponseEmpty);
	}
	qos_hex::decode(&text)
		.map(Zeroizing::new)
		.map_err(|e| OtpError::ResponseNotHex(format!("{e:?}")))
}

fn pair_from_response(
	response: &[u8],
	salt: &[u8],
) -> Result<HybridPair, OtpError> {
	let mut seed = Zeroizing::new([0u8; MASTER_SEED_LEN]);
	Hkdf::<Sha512>::new(Some(salt), response)
		.expand(OTP_SEED_INFO, &mut *seed)
		.map_err(|_| HybridError::HkdfExpansionFailed)?;
	HybridPair::from_master_seed(&seed).map_err(Into::into)
}

/// Derive the member pair for `salt` from one device response.
///
/// # Errors
///
/// Returns [`OtpError`] if the command is refused or fails, or the pair
/// cannot be built.
pub fn derive_member_pair(
	command: &str,
	salt: &[u8],
) -> Result<HybridPair, OtpError> {
	pair_from_response(&respond(command, salt)?, salt)
}

/// Derive the member pair for `salt`, first proving the device answers the
/// challenge and answers it the same way twice. Use when minting a key, where
/// a bad command would otherwise register a key nobody can derive again.
///
/// # Errors
///
/// Returns [`OtpError::ChallengeIgnored`] or [`OtpError::ResponseUnstable`]
/// for a command that would not reproduce the key, and [`OtpError`] for any
/// other failure.
pub fn derive_member_pair_probed(
	command: &str,
	salt: &[u8],
) -> Result<HybridPair, OtpError> {
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

	pair_from_response(&first, salt)
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

	const ECHO_COMMAND: &str = "printf '%s' {challenge}";

	#[test]
	fn same_salt_derives_the_same_pair() {
		let salt = fresh_salt();

		let first = derive_member_pair(ECHO_COMMAND, &salt).unwrap();
		let second = derive_member_pair_probed(ECHO_COMMAND, &salt).unwrap();

		assert!(first.public_key() == second.public_key());
	}

	#[test]
	fn different_salts_derive_different_pairs() {
		let first = derive_member_pair(ECHO_COMMAND, &fresh_salt()).unwrap();
		let second = derive_member_pair(ECHO_COMMAND, &fresh_salt()).unwrap();

		assert!(first.public_key() != second.public_key());
	}

	#[test]
	fn command_without_placeholder_is_refused() {
		assert!(matches!(
			derive_member_pair("echo 00", &fresh_salt()),
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
			derive_member_pair_probed("echo 00 # {challenge}", &fresh_salt()),
			Err(OtpError::ChallengeIgnored)
		));
	}

	#[test]
	fn probe_rejects_an_unstable_command() {
		let unstable =
			"od -An -N16 -tx1 /dev/urandom | tr -d ' \\n' # {challenge}";

		assert!(matches!(
			derive_member_pair_probed(unstable, &fresh_salt()),
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
