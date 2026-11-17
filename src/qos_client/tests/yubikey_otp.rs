#![allow(missing_docs)]

use std::process::Command;

use qos_test_primitives::PathWrapper;

const QOS_CLIENT_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/qos_client");
/// Stands in for OTP slot 2: answers each challenge with 20 bytes of it.
const STAND_IN_DEVICE: &str = "printf '%s' {challenge} | cut -c1-40";

fn qos_client(args: &[&str]) -> std::process::Output {
	Command::new(QOS_CLIENT_PATH).args(args).output().unwrap()
}

#[test]
fn provisioned_member_key_needs_the_passphrase() {
	let dir = PathWrapper::from("/tmp/qos_client_yubikey_otp_passphrase");
	std::fs::create_dir_all(&*dir).unwrap();
	let pub_path = dir.join("member.pub");
	let salt_path = dir.join("member.salt");
	let passphrase_path = dir.join("passphrase");
	let wrong_passphrase_path = dir.join("wrong_passphrase");
	std::fs::write(&passphrase_path, "correct horse battery\n").unwrap();
	std::fs::write(&wrong_passphrase_path, "correct horse battery!\n").unwrap();

	let provision = qos_client(&[
		"provision-yubikey",
		"--pub-path",
		pub_path.to_str().unwrap(),
		"--yubikey-salt-path",
		salt_path.to_str().unwrap(),
		"--challenge-command",
		STAND_IN_DEVICE,
		"--yubikey-passphrase-path",
		passphrase_path.to_str().unwrap(),
	]);
	assert!(provision.status.success(), "{provision:?}");
	let provisioned = std::fs::read_to_string(&pub_path).unwrap();

	let public = |passphrase: &std::path::Path| {
		let out = qos_client(&[
			"yubikey-public",
			"--yubikey-salt-path",
			salt_path.to_str().unwrap(),
			"--challenge-command",
			STAND_IN_DEVICE,
			"--yubikey-passphrase-path",
			passphrase.to_str().unwrap(),
		]);
		assert!(out.status.success(), "{out:?}");
		String::from_utf8(out.stdout).unwrap().trim().to_owned()
	};

	assert_eq!(public(&passphrase_path), provisioned.trim());
	assert_ne!(
		public(&wrong_passphrase_path),
		provisioned.trim(),
		"the device's answer to the salt alone must not rebuild the key"
	);
}

#[test]
fn yubikey_without_a_salt_path_is_an_error_not_a_panic() {
	let out = qos_client(&["yubikey-public"]);

	assert!(!out.status.success());
	assert!(
		!String::from_utf8_lossy(&out.stderr).contains("panicked"),
		"{out:?}"
	);
}
