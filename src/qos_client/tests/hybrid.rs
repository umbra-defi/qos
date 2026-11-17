#![allow(missing_docs)]

use std::{path::PathBuf, process::Command};

use qos_test_primitives::PathWrapper;

const DATA: &str = "test data";
const MOCK_PRIMARY_SEED_PATH: &str = "./tests/mock/primary.secret.keep";
const MOCK_PRIMARY_PUB_PATH: &str = "./tests/mock/primary.pub";
const QOS_CLIENT_PATH: &str =
	concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/debug/qos_client");

#[test]
fn hybrid_sign_verify_roundtrip() {
	let tmp = PathWrapper::from("/tmp/hybrid_sign_verify_roundtrip");
	std::fs::create_dir_all(&*tmp).unwrap();

	let payload_path = "/tmp/hybrid_sign_verify_roundtrip/payload";
	let signature_path = "/tmp/hybrid_sign_verify_roundtrip/signature";

	std::fs::write(payload_path, DATA).unwrap();
	// Sanity check the signature output doesn't already exist
	assert!(!PathBuf::from(signature_path).exists());

	assert!(
		Command::new(QOS_CLIENT_PATH)
			.arg("hybrid-sign")
			.arg("--payload-path")
			.arg(payload_path)
			.arg("--signature-path")
			.arg(signature_path)
			.arg("--master-seed-path")
			.arg(MOCK_PRIMARY_SEED_PATH)
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success()
	);

	let signature = std::fs::read_to_string(signature_path).unwrap();
	assert_eq!(
		qos_hex::decode(&signature).unwrap().len(),
		qos_hybrid::SIGNATURE_LEN,
		"hybrid-sign must write one hex ML-DSA-87 signature"
	);

	assert!(
		Command::new(QOS_CLIENT_PATH)
			.arg("hybrid-verify")
			.arg("--payload-path")
			.arg(payload_path)
			.arg("--signature-path")
			.arg(signature_path)
			.arg("--pub-path")
			.arg(MOCK_PRIMARY_PUB_PATH)
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success()
	);
}

#[test]
fn hybrid_asymmetric_encrypt_decrypt_roundtrip() {
	let tmp =
		PathWrapper::from("/tmp/hybrid_asymmetric_encrypt_decrypt_roundtrip");
	std::fs::create_dir_all(&*tmp).unwrap();

	let plaintext_input_path =
		"/tmp/hybrid_asymmetric_encrypt_decrypt_roundtrip/plaintext_input";
	std::fs::write(plaintext_input_path, DATA.as_bytes()).unwrap();
	let ciphertext_path =
		"/tmp/hybrid_asymmetric_encrypt_decrypt_roundtrip/ciphertext";
	// Sanity check the ciphertext output doesn't already exist
	assert!(!PathBuf::from(ciphertext_path).exists());

	assert!(
		Command::new(QOS_CLIENT_PATH)
			.arg("hybrid-asymmetric-encrypt")
			.arg("--plaintext-path")
			.arg(plaintext_input_path)
			.arg("--ciphertext-path")
			.arg(ciphertext_path)
			.arg("--pub-path")
			.arg(MOCK_PRIMARY_PUB_PATH)
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success()
	);

	let plaintext_output_path =
		"/tmp/hybrid_asymmetric_encrypt_decrypt_roundtrip/plaintext_output";
	assert!(!PathBuf::from(plaintext_output_path).exists());

	assert!(
		Command::new(QOS_CLIENT_PATH)
			.arg("hybrid-asymmetric-decrypt")
			.arg("--plaintext-path")
			.arg(plaintext_output_path)
			.arg("--ciphertext-path")
			.arg(ciphertext_path)
			.arg("--master-seed-path")
			.arg(MOCK_PRIMARY_SEED_PATH)
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success()
	);

	let decrypted_bytes = std::fs::read(plaintext_output_path).unwrap();
	assert_eq!(decrypted_bytes, DATA.as_bytes());

	let hex_plaintext_output_path =
		"/tmp/hybrid_asymmetric_encrypt_decrypt_roundtrip/plaintext_output";
	assert!(
		Command::new(QOS_CLIENT_PATH)
			.arg("hybrid-asymmetric-decrypt")
			.arg("--plaintext-path")
			.arg(hex_plaintext_output_path)
			.arg("--ciphertext-path")
			.arg(ciphertext_path)
			.arg("--master-seed-path")
			.arg(MOCK_PRIMARY_SEED_PATH)
			.arg("--output-hex")
			.spawn()
			.unwrap()
			.wait()
			.unwrap()
			.success()
	);

	let hex_plaintext = std::fs::read_to_string(plaintext_output_path).unwrap();

	assert_eq!(qos_hex::decode(&hex_plaintext).unwrap(), decrypted_bytes);
}
