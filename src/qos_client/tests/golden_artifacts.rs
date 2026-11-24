#![allow(missing_docs)]

use std::{
	path::PathBuf,
	process::{Command, Output},
	time::{SystemTime, UNIX_EPOCH},
};

use qos_test_primitives::PathWrapper;

const QOS_CLIENT: &str = env!("CARGO_BIN_EXE_qos_client");
const PIVOT_BYTES: &[u8] = b"mono compat pivot bytes";
const PIVOT_SHA256_HEX: &str =
	"6851e7d5d3200c971307b7f3d02c35dc685413215392f1b35fa5ecb53264d963";
const MANIFEST_BORSH_LEN: usize = 17812;
const MANIFEST_BORSH_SHA256_HEX: &str =
	"43ddbcdecff83b1855d7957a6abb5a6bb8cf801991cdff5656ff0f5364b852e5";
const MANIFEST_ENVELOPE_BORSH_LEN: usize = 26750;
const MANIFEST_V0_BORSH_LEN: usize = 17798;
const MANIFEST_V0_BORSH_SHA256_HEX: &str =
	"8297c1120778d5ba6817feb5716266ec6f98e88c60a49ec0b978785571fd4287";

const EXPECTED_MANIFEST_JSON_TEMPLATE: &str = concat!(
	"{\"namespace\":{\"name\":\"production/signer\",\"nonce\"",
	":31,\"quorumKey\":\"{KEY}\"},\"pivot\":{\"hash\":\"6851e",
	"7d5d3200c971307b7f3d02c35dc685413215392f1b35fa5ecb53264d",
	"963\",\"restart\":\"Always\",\"bridgeConfig\":[{\"type\"",
	":\"server\",\"port\":3000,\"host\":\"0.0.0.0\"}],\"debug",
	"Mode\":true,\"args\":[\"--config\",\"/etc/config.json\"]",
	"},\"manifestSet\":{\"threshold\":1,\"members\":[{\"alias",
	"\":\"dev\",\"pubKey\":\"{KEY}\"}]},\"shareSet\":{\"thres",
	"hold\":1,\"members\":[{\"alias\":\"dev\",\"pubKey\":\"{K",
	"EY}\"}]},\"enclave\":{\"pcr0\":\"181bd012baaecfd0bd4d6f6",
	"17bea65ad5a76413d2a0c09b18efe72bff3fdc4b55f7416ec6d88a4d",
	"3236ce02d83b5eb8b\",\"pcr1\":\"181bd012baaecfd0bd4d6f617",
	"bea65ad5a76413d2a0c09b18efe72bff3fdc4b55f7416ec6d88a4d32",
	"36ce02d83b5eb8b\",\"pcr2\":\"21b9efbc184807662e966d34f39",
	"0821309eeac6802309798826296bf3e8bec7c10edb30948c90ba6731",
	"0f7b964fc500a\",\"pcr3\":\"78fce75db17cd4e0a3fb8dad3ad12",
	"8ca5e77edbb2b2c7f75329dccd99aa5f6ef4fc1f1a452e315b9e98f9",
	"e312e6921e6\",\"awsRootCertificate\":\"3082021130820196a",
	"003020102021100f93175681b90afe11d46ccb4e4e7f856300a06082",
	"a8648ce3d0403033049310b3009060355040613025553310f300d060",
	"355040a0c06416d617a6f6e310c300a060355040b0c03415753311b3",
	"01906035504030c126177732e6e6974726f2d656e636c61766573301",
	"e170d3139313032383133323830355a170d343931303238313432383",
	"0355a3049310b3009060355040613025553310f300d060355040a0c0",
	"6416d617a6f6e310c300a060355040b0c03415753311b30190603550",
	"4030c126177732e6e6974726f2d656e636c617665733076301006072",
	"a8648ce3d020106052b8104002203620004fc0254eba608c1f36870e",
	"29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe",
	"3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6",
	"f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53",
	"ff4a3423040300f0603551d130101ff040530030101ff301d0603551",
	"d0e041604149025b50dd90547e796c396fa729dcf99a9df4b96300e0",
	"603551d0f0101ff040403020186300a06082a8648ce3d04030303690",
	"03066023100a37f2f91a1c9bd5ee7b8627c1698d255038e1f0343f95",
	"b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6adf302310",
	"0a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a53197",
	"f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff6\",\"qosCommit",
	"\":\"\"},\"patchSet\":{\"threshold\":1,\"members\":[{\"p",
	"ubKey\":\"{KEY}\"}]}}",
);

const EXPECTED_APPROVAL_JSON_TEMPLATE: &str = concat!(
	"{\"signature\":\"{SIG}\",\"member\":{\"alias\":\"dev\",",
	"\"pubKey\":\"{KEY}\"}}",
);

const EXPECTED_MANIFEST_ENVELOPE_JSON_TEMPLATE: &str = concat!(
	"{\"manifest\":{\"namespace\":{\"name\":\"production/sign",
	"er\",\"nonce\":31,\"quorumKey\":\"{KEY}\"},\"pivot\":{\"",
	"hash\":\"6851e7d5d3200c971307b7f3d02c35dc685413215392f1b",
	"35fa5ecb53264d963\",\"restart\":\"Always\",\"bridgeConfi",
	"g\":[{\"type\":\"server\",\"port\":3000,\"host\":\"0.0.0",
	".0\"}],\"debugMode\":true,\"args\":[\"--config\",\"/etc/",
	"config.json\"]},\"manifestSet\":{\"threshold\":1,\"membe",
	"rs\":[{\"alias\":\"dev\",\"pubKey\":\"{KEY}\"}]},\"share",
	"Set\":{\"threshold\":1,\"members\":[{\"alias\":\"dev\",",
	"\"pubKey\":\"{KEY}\"}]},\"enclave\":{\"pcr0\":\"181bd012",
	"baaecfd0bd4d6f617bea65ad5a76413d2a0c09b18efe72bff3fdc4b5",
	"5f7416ec6d88a4d3236ce02d83b5eb8b\",\"pcr1\":\"181bd012ba",
	"aecfd0bd4d6f617bea65ad5a76413d2a0c09b18efe72bff3fdc4b55f",
	"7416ec6d88a4d3236ce02d83b5eb8b\",\"pcr2\":\"21b9efbc1848",
	"07662e966d34f390821309eeac6802309798826296bf3e8bec7c10ed",
	"b30948c90ba67310f7b964fc500a\",\"pcr3\":\"78fce75db17cd4",
	"e0a3fb8dad3ad128ca5e77edbb2b2c7f75329dccd99aa5f6ef4fc1f1",
	"a452e315b9e98f9e312e6921e6\",\"awsRootCertificate\":\"30",
	"82021130820196a003020102021100f93175681b90afe11d46ccb4e4",
	"e7f856300a06082a8648ce3d0403033049310b300906035504061302",
	"5553310f300d060355040a0c06416d617a6f6e310c300a060355040b",
	"0c03415753311b301906035504030c126177732e6e6974726f2d656e",
	"636c61766573301e170d3139313032383133323830355a170d343931",
	"3032383134323830355a3049310b3009060355040613025553310f30",
	"0d060355040a0c06416d617a6f6e310c300a060355040b0c03415753",
	"311b301906035504030c126177732e6e6974726f2d656e636c617665",
	"733076301006072a8648ce3d020106052b8104002203620004fc0254",
	"eba608c1f36870e29ada90be46383292736e894bfff672d989444b50",
	"51e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e7",
	"52cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487",
	"c9796284304dc53ff4a3423040300f0603551d130101ff0405300301",
	"01ff301d0603551d0e041604149025b50dd90547e796c396fa729dcf",
	"99a9df4b96300e0603551d0f0101ff040403020186300a06082a8648",
	"ce3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c1698d2",
	"55038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71",
	"b4c3d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde",
	"8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff6",
	"\",\"qosCommit\":\"\"},\"patchSet\":{\"threshold\":1,\"m",
	"embers\":[{\"pubKey\":\"{KEY}\"}]}},\"manifestSetApprova",
	"ls\":[{\"signature\":\"{SIG}\",\"member\":{\"alias\":\"d",
	"ev\",\"pubKey\":\"{KEY}\"}}],\"shareSetApprovals\":[]}",
);

const EXPECTED_MANIFEST_V0_JSON_TEMPLATE: &str = concat!(
	"{\"namespace\":{\"name\":\"production/signer\",\"nonce\"",
	":31,\"quorumKey\":\"{KEY}\"},\"pivot\":{\"hash\":\"6851e",
	"7d5d3200c971307b7f3d02c35dc685413215392f1b35fa5ecb53264d",
	"963\",\"restart\":\"Always\",\"args\":[\"--config\",\"/e",
	"tc/config.json\"]},\"manifestSet\":{\"threshold\":1,\"me",
	"mbers\":[{\"alias\":\"dev\",\"pubKey\":\"{KEY}\"}]},\"sh",
	"areSet\":{\"threshold\":1,\"members\":[{\"alias\":\"dev",
	"\",\"pubKey\":\"{KEY}\"}]},\"enclave\":{\"pcr0\":\"181bd",
	"012baaecfd0bd4d6f617bea65ad5a76413d2a0c09b18efe72bff3fdc",
	"4b55f7416ec6d88a4d3236ce02d83b5eb8b\",\"pcr1\":\"181bd01",
	"2baaecfd0bd4d6f617bea65ad5a76413d2a0c09b18efe72bff3fdc4b",
	"55f7416ec6d88a4d3236ce02d83b5eb8b\",\"pcr2\":\"21b9efbc1",
	"84807662e966d34f390821309eeac6802309798826296bf3e8bec7c1",
	"0edb30948c90ba67310f7b964fc500a\",\"pcr3\":\"78fce75db17",
	"cd4e0a3fb8dad3ad128ca5e77edbb2b2c7f75329dccd99aa5f6ef4fc",
	"1f1a452e315b9e98f9e312e6921e6\",\"awsRootCertificate\":",
	"\"3082021130820196a003020102021100f93175681b90afe11d46cc",
	"b4e4e7f856300a06082a8648ce3d0403033049310b30090603550406",
	"13025553310f300d060355040a0c06416d617a6f6e310c300a060355",
	"040b0c03415753311b301906035504030c126177732e6e6974726f2d",
	"656e636c61766573301e170d3139313032383133323830355a170d34",
	"39313032383134323830355a3049310b300906035504061302555331",
	"0f300d060355040a0c06416d617a6f6e310c300a060355040b0c0341",
	"5753311b301906035504030c126177732e6e6974726f2d656e636c61",
	"7665733076301006072a8648ce3d020106052b8104002203620004fc",
	"0254eba608c1f36870e29ada90be46383292736e894bfff672d98944",
	"4b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b",
	"66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf6301280966",
	"4487c9796284304dc53ff4a3423040300f0603551d130101ff040530",
	"030101ff301d0603551d0e041604149025b50dd90547e796c396fa72",
	"9dcf99a9df4b96300e0603551d0f0101ff040403020186300a06082a",
	"8648ce3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c16",
	"98d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8ae",
	"ee71b4c3d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4",
	"fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d2302f3",
	"dff6\",\"qosCommit\":\"\"},\"patchSet\":{\"threshold\":1",
	",\"members\":[{\"pubKey\":\"{KEY}\"}]}}",
);

struct Fixture {
	_tmp: PathWrapper<PathBuf>,
	manifest_set: PathBuf,
	share_set: PathBuf,
	patch_set: PathBuf,
	approvals_dir: PathBuf,
	manifest_path: PathBuf,
	envelope_path: PathBuf,
	approval_path: PathBuf,
	manifest_borsh_path: PathBuf,
	envelope_borsh_path: PathBuf,
	manifest_v0_json_path: PathBuf,
	manifest_v0_borsh_path: PathBuf,
	pivot_path: PathBuf,
	pivot_hash_path: PathBuf,
	qos_release_dir: PathBuf,
	pcr3_preimage_path: PathBuf,
	quorum_key_path: PathBuf,
	secret_path: PathBuf,
}

impl Fixture {
	fn new(test_name: &str) -> Self {
		let nanos =
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
		let root = std::env::temp_dir().join(format!(
			"qos_client_golden_{test_name}_{}_{}",
			std::process::id(),
			nanos
		));
		let root = PathWrapper::from(root);

		let manifest_set = root.join("manifest-set");
		let share_set = root.join("share-set");
		let patch_set = root.join("patch-set");
		let approvals_dir = root.join("approvals");
		let qos_release_dir = root.join("dist");
		for dir in [
			&manifest_set,
			&share_set,
			&patch_set,
			&approvals_dir,
			&qos_release_dir,
		] {
			std::fs::create_dir_all(dir).unwrap();
		}

		let manifest_path = root.join("manifest");
		let envelope_path = approvals_dir.join("manifest_envelope");
		let approval_path =
			approvals_dir.join("dev-production-signer-31.approval");
		let manifest_borsh_path = root.join("manifest.borsh");
		let envelope_borsh_path = root.join("manifest_envelope.borsh");
		let manifest_v0_json_path = root.join("manifest_v0.json");
		let manifest_v0_borsh_path = root.join("manifest_v0.borsh");
		let pivot_path = root.join("pivot.bin");
		let pivot_hash_path = root.join("pivot.hash");
		let pcr3_preimage_path = root.join("pcr3_preimage");
		let quorum_key_path = root.join("quorum_key.pub");

		let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		let primary_pub = manifest_dir.join("tests/mock/primary.pub");
		let secret_path = manifest_dir.join("tests/mock/primary.secret.keep");
		let integration_dist =
			manifest_dir.join("../integration/mock/dist/aws-x86_64.pcrs");
		let integration_pcr3 = manifest_dir
			.join("../integration/mock/namespaces/pcr3-preimage.txt");

		for set_dir in [&manifest_set, &share_set, &patch_set] {
			std::fs::write(set_dir.join("quorum_threshold"), b"1\n").unwrap();
			std::fs::copy(&primary_pub, set_dir.join("dev.pub")).unwrap();
		}
		std::fs::copy(&primary_pub, &quorum_key_path).unwrap();
		write_quorum_key_envelope(&primary_pub, &root);
		std::fs::copy(
			integration_dist,
			qos_release_dir.join("aws-x86_64.pcrs"),
		)
		.unwrap();
		std::fs::copy(integration_pcr3, &pcr3_preimage_path).unwrap();
		std::fs::write(&pivot_path, PIVOT_BYTES).unwrap();

		Self {
			_tmp: root,
			manifest_set,
			share_set,
			patch_set,
			approvals_dir,
			manifest_path,
			envelope_path,
			approval_path,
			manifest_borsh_path,
			envelope_borsh_path,
			manifest_v0_json_path,
			manifest_v0_borsh_path,
			pivot_path,
			pivot_hash_path,
			qos_release_dir,
			pcr3_preimage_path,
			quorum_key_path,
			secret_path,
		}
	}

	fn generate_artifacts(&self) {
		assert_success(&run_qos_client([
			"pivot-hash",
			"--output-path",
			self.pivot_hash_path.to_str().unwrap(),
			"--pivot-path",
			self.pivot_path.to_str().unwrap(),
		]));

		assert_success(&run_qos_client([
			"generate-manifest",
			"--nonce",
			"31",
			"--namespace",
			"production/signer",
			"--restart-policy",
			"always",
			"--manifest-path",
			self.manifest_path.to_str().unwrap(),
			"--pivot-hash-path",
			self.pivot_hash_path.to_str().unwrap(),
			"--qos-release-dir",
			self.qos_release_dir.to_str().unwrap(),
			"--pcr3-preimage-path",
			self.pcr3_preimage_path.to_str().unwrap(),
			"--pivot-args",
			"[--config,/etc/config.json]",
			"--manifest-set-dir",
			self.manifest_set.to_str().unwrap(),
			"--share-set-dir",
			self.share_set.to_str().unwrap(),
			"--patch-set-dir",
			self.patch_set.to_str().unwrap(),
			"--quorum-key-path",
			self.quorum_key_path.to_str().unwrap(),
			"--debug-mode",
			"true",
			"--bridge-config",
			"[{\"type\":\"server\",\"port\":3000,\"host\":\"0.0.0.0\"}]",
		]));

		assert_success(&run_qos_client([
			"approve-manifest",
			"--alias",
			"dev",
			"--manifest-approvals-dir",
			self.approvals_dir.to_str().unwrap(),
			"--manifest-path",
			self.manifest_path.to_str().unwrap(),
			"--manifest-set-dir",
			self.manifest_set.to_str().unwrap(),
			"--patch-set-dir",
			self.patch_set.to_str().unwrap(),
			"--share-set-dir",
			self.share_set.to_str().unwrap(),
			"--pcr3-preimage-path",
			self.pcr3_preimage_path.to_str().unwrap(),
			"--pivot-hash-path",
			self.pivot_hash_path.to_str().unwrap(),
			"--qos-release-dir",
			self.qos_release_dir.to_str().unwrap(),
			"--quorum-key-path",
			self.quorum_key_path.to_str().unwrap(),
			"--secret-path",
			self.secret_path.to_str().unwrap(),
			"--unsafe-auto-confirm",
		]));

		assert_success(&run_qos_client([
			"generate-manifest-envelope",
			"--manifest-approvals-dir",
			self.approvals_dir.to_str().unwrap(),
			"--manifest-path",
			self.manifest_path.to_str().unwrap(),
		]));
	}
}

/// Writes a quorum key envelope dealt over the fixture's one-member share set
/// beside `quorum_key.pub`, where generate-manifest and approve-manifest read
/// it. The sealed seed is arbitrary: these commands only name the envelope.
fn write_quorum_key_envelope(
	member_pub: &std::path::Path,
	root: &std::path::Path,
) {
	use qos_core::protocol::services::{
		boot::{QuorumMember, ShareHolderNode, ShareNode},
		envelope::seal_quorum_key,
		genesis::GenesisSet,
	};
	let pub_key =
		qos_hybrid::HybridPublic::from_hex_file(member_pub).unwrap().to_bytes();
	let set = GenesisSet {
		threshold: 1,
		members: vec![QuorumMember {
			alias: "dev".to_string(),
			pub_key: pub_key.clone(),
		}],
		groups: vec![],
	};
	let tree = set.holder_set().unwrap().tree().unwrap();
	let (envelope, _) = seal_quorum_key(&[7; 32], &pub_key, &tree).unwrap();
	std::fs::write(root.join("quorum_key.envelope"), envelope.encode())
		.unwrap();
}

fn run_qos_client<const N: usize>(args: [&str; N]) -> Output {
	Command::new(QOS_CLIENT).args(args).output().unwrap()
}

fn assert_success(output: &Output) {
	assert!(
		output.status.success(),
		"qos_client failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
		output.status.code(),
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr),
	);
}

fn assert_failure(output: &Output) {
	assert!(
		!output.status.success(),
		"qos_client unexpectedly succeeded\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
		output.status.code(),
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr),
	);
}

fn assert_file_json_exact(path: &std::path::Path, expected: &str) {
	let actual = std::fs::read_to_string(path).unwrap();
	assert_eq!(actual, expected);
}

fn assert_file_borsh_hash(
	path: &std::path::Path,
	expected_len: usize,
	expected_sha256_hex: &str,
) {
	let bytes = std::fs::read(path).unwrap();
	assert_eq!(bytes.len(), expected_len);
	assert_eq!(
		qos_hex::encode(&qos_crypto::sha_256(&bytes)),
		expected_sha256_hex
	);
}

/// Fill a golden template with the mock primary public key and `signature`.
/// The key's bytes are pinned by `qos_hybrid`'s compatibility vectors and
/// ML-DSA-87 signatures are hedged, so the templates pin everything else.
fn fill(template: &str, signature: &str) -> String {
	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	let key =
		std::fs::read_to_string(manifest_dir.join("tests/mock/primary.pub"))
			.unwrap();
	template.replace("{KEY}", key.trim()).replace("{SIG}", signature)
}

#[test]
fn golden_manifest_approval_and_envelope_raw_bytes() {
	let fixture = Fixture::new("artifacts");
	fixture.generate_artifacts();

	assert_eq!(
		std::fs::read_to_string(&fixture.pivot_hash_path).unwrap(),
		PIVOT_SHA256_HEX
	);

	assert_file_json_exact(
		&fixture.manifest_path,
		&fill(EXPECTED_MANIFEST_JSON_TEMPLATE, ""),
	);

	let approval: serde_json::Value =
		serde_json::from_slice(&std::fs::read(&fixture.approval_path).unwrap())
			.unwrap();
	let signature = approval["signature"].as_str().unwrap().to_owned();
	assert_file_json_exact(
		&fixture.approval_path,
		&fill(EXPECTED_APPROVAL_JSON_TEMPLATE, &signature),
	);
	assert_file_json_exact(
		&fixture.envelope_path,
		&fill(EXPECTED_MANIFEST_ENVELOPE_JSON_TEMPLATE, &signature),
	);
	assert_success(&run_qos_client([
		"json-to-borsh",
		"--display-type",
		"manifest",
		"--file-path",
		fixture.manifest_path.to_str().unwrap(),
		"--output-path",
		fixture.manifest_borsh_path.to_str().unwrap(),
	]));
	let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
	qos_hybrid::HybridPublic::from_hex_file(
		manifest_dir.join("tests/mock/primary.pub"),
	)
	.unwrap()
	.verify(
		&qos_crypto::sha_256(
			&std::fs::read(&fixture.manifest_borsh_path).unwrap(),
		),
		&qos_hex::decode(&signature).unwrap(),
	)
	.expect("the approval must be the primary key signing the manifest hash");
	assert_success(&run_qos_client([
		"json-to-borsh",
		"--display-type",
		"manifest-envelope",
		"--file-path",
		fixture.envelope_path.to_str().unwrap(),
		"--output-path",
		fixture.envelope_borsh_path.to_str().unwrap(),
	]));

	let manifest_v0_json = fill(EXPECTED_MANIFEST_V0_JSON_TEMPLATE, "");
	std::fs::write(&fixture.manifest_v0_json_path, &manifest_v0_json).unwrap();
	assert_success(&run_qos_client([
		"json-to-borsh",
		"--display-type",
		"manifest",
		"--file-path",
		fixture.manifest_v0_json_path.to_str().unwrap(),
		"--output-path",
		fixture.manifest_v0_borsh_path.to_str().unwrap(),
	]));

	assert_file_borsh_hash(
		&fixture.manifest_borsh_path,
		MANIFEST_BORSH_LEN,
		MANIFEST_BORSH_SHA256_HEX,
	);
	assert_eq!(
		std::fs::read(&fixture.envelope_borsh_path).unwrap().len(),
		MANIFEST_ENVELOPE_BORSH_LEN,
		"the envelope's hash moves with its hedged signature, so only its \
		 length is pinned"
	);
	assert_file_borsh_hash(
		&fixture.manifest_v0_borsh_path,
		MANIFEST_V0_BORSH_LEN,
		MANIFEST_V0_BORSH_SHA256_HEX,
	);
}

#[test]
#[allow(clippy::too_many_lines)]
fn v2_commands_generate_approve_and_envelope_use_json_hash() {
	use qos_core::protocol::services::boot::{
		Approval, ManifestEnvelopeV2, ManifestV2, ManifestVersion,
	};
	use qos_hybrid::HybridPublic;

	let fixture = Fixture::new("v2_commands");

	assert_success(&run_qos_client([
		"pivot-hash",
		"--output-path",
		fixture.pivot_hash_path.to_str().unwrap(),
		"--pivot-path",
		fixture.pivot_path.to_str().unwrap(),
	]));

	assert_success(&run_qos_client([
		"generate-manifest",
		"--use-manifest-version",
		"2",
		"--nonce",
		"31",
		"--namespace",
		"production/signer",
		"--restart-policy",
		"always",
		"--manifest-path",
		fixture.manifest_path.to_str().unwrap(),
		"--pivot-hash-path",
		fixture.pivot_hash_path.to_str().unwrap(),
		"--qos-release-dir",
		fixture.qos_release_dir.to_str().unwrap(),
		"--pcr3-preimage-path",
		fixture.pcr3_preimage_path.to_str().unwrap(),
		"--pivot-args",
		"[--config,/etc/config.json]",
		"--manifest-set-dir",
		fixture.manifest_set.to_str().unwrap(),
		"--share-set-dir",
		fixture.share_set.to_str().unwrap(),
		"--quorum-key-path",
		fixture.quorum_key_path.to_str().unwrap(),
		"--debug-mode",
		"true",
		"--bridge-config",
		"[{\"type\":\"server\",\"port\":3000,\"host\":\"0.0.0.0\"}]",
		"--dns-resolvers",
		"[1.1.1.1,2606:4700:4700::1111]",
	]));

	let manifest_json: serde_json::Value =
		serde_json::from_slice(&std::fs::read(&fixture.manifest_path).unwrap())
			.unwrap();
	assert_eq!(manifest_json["version"], "v2");
	assert!(manifest_json.get("patchSet").is_none());
	assert_eq!(manifest_json["dns"]["resolvers"][0], "1.1.1.1");
	assert_eq!(manifest_json["dns"]["resolvers"][1], "2606:4700:4700::1111");

	let manifest: ManifestV2 =
		serde_json::from_value(manifest_json.clone()).unwrap();
	assert_eq!(manifest.version, ManifestVersion::V2);
	let manifest_hash = qos_json::hash(&manifest).unwrap();

	assert_success(&run_qos_client([
		"approve-manifest",
		"--alias",
		"dev",
		"--manifest-approvals-dir",
		fixture.approvals_dir.to_str().unwrap(),
		"--manifest-path",
		fixture.manifest_path.to_str().unwrap(),
		"--manifest-set-dir",
		fixture.manifest_set.to_str().unwrap(),
		"--share-set-dir",
		fixture.share_set.to_str().unwrap(),
		"--pcr3-preimage-path",
		fixture.pcr3_preimage_path.to_str().unwrap(),
		"--pivot-hash-path",
		fixture.pivot_hash_path.to_str().unwrap(),
		"--qos-release-dir",
		fixture.qos_release_dir.to_str().unwrap(),
		"--quorum-key-path",
		fixture.quorum_key_path.to_str().unwrap(),
		"--secret-path",
		fixture.secret_path.to_str().unwrap(),
		"--unsafe-auto-confirm",
	]));

	let approval: Approval =
		serde_json::from_slice(&std::fs::read(&fixture.approval_path).unwrap())
			.unwrap();
	let pub_key = HybridPublic::from_bytes(&approval.member.pub_key).unwrap();
	assert!(pub_key.verify(&manifest_hash, &approval.signature).is_ok());

	assert_success(&run_qos_client([
		"generate-manifest-envelope",
		"--manifest-approvals-dir",
		fixture.approvals_dir.to_str().unwrap(),
		"--manifest-path",
		fixture.manifest_path.to_str().unwrap(),
	]));

	let envelope: ManifestEnvelopeV2 =
		serde_json::from_slice(&std::fs::read(&fixture.envelope_path).unwrap())
			.unwrap();
	assert_eq!(envelope.manifest.version, ManifestVersion::V2);
	assert_eq!(envelope.manifest_set_approvals.len(), 1);
	assert!(
		HybridPublic::from_bytes(
			&envelope.manifest_set_approvals[0].member.pub_key
		)
		.unwrap()
		.verify(&manifest_hash, &envelope.manifest_set_approvals[0].signature)
		.is_ok()
	);
}

#[test]
fn v2_commands_json_to_borsh_rejected() {
	let fixture = Fixture::new("v2_json_to_borsh_rejected");

	assert_success(&run_qos_client([
		"pivot-hash",
		"--output-path",
		fixture.pivot_hash_path.to_str().unwrap(),
		"--pivot-path",
		fixture.pivot_path.to_str().unwrap(),
	]));

	assert_success(&run_qos_client([
		"generate-manifest",
		"--use-manifest-version",
		"2",
		"--nonce",
		"31",
		"--namespace",
		"production/signer",
		"--restart-policy",
		"always",
		"--manifest-path",
		fixture.manifest_path.to_str().unwrap(),
		"--pivot-hash-path",
		fixture.pivot_hash_path.to_str().unwrap(),
		"--qos-release-dir",
		fixture.qos_release_dir.to_str().unwrap(),
		"--pcr3-preimage-path",
		fixture.pcr3_preimage_path.to_str().unwrap(),
		"--pivot-args",
		"[--config,/etc/config.json]",
		"--manifest-set-dir",
		fixture.manifest_set.to_str().unwrap(),
		"--share-set-dir",
		fixture.share_set.to_str().unwrap(),
		"--quorum-key-path",
		fixture.quorum_key_path.to_str().unwrap(),
		"--debug-mode",
		"true",
		"--bridge-config",
		"[{\"type\":\"server\",\"port\":3000,\"host\":\"0.0.0.0\"}]",
	]));

	assert_success(&run_qos_client([
		"approve-manifest",
		"--alias",
		"dev",
		"--manifest-approvals-dir",
		fixture.approvals_dir.to_str().unwrap(),
		"--manifest-path",
		fixture.manifest_path.to_str().unwrap(),
		"--manifest-set-dir",
		fixture.manifest_set.to_str().unwrap(),
		"--share-set-dir",
		fixture.share_set.to_str().unwrap(),
		"--pcr3-preimage-path",
		fixture.pcr3_preimage_path.to_str().unwrap(),
		"--pivot-hash-path",
		fixture.pivot_hash_path.to_str().unwrap(),
		"--qos-release-dir",
		fixture.qos_release_dir.to_str().unwrap(),
		"--quorum-key-path",
		fixture.quorum_key_path.to_str().unwrap(),
		"--secret-path",
		fixture.secret_path.to_str().unwrap(),
		"--unsafe-auto-confirm",
	]));

	assert_success(&run_qos_client([
		"generate-manifest-envelope",
		"--manifest-approvals-dir",
		fixture.approvals_dir.to_str().unwrap(),
		"--manifest-path",
		fixture.manifest_path.to_str().unwrap(),
	]));

	let manifest_out = run_qos_client([
		"json-to-borsh",
		"--display-type",
		"manifest",
		"--file-path",
		fixture.manifest_path.to_str().unwrap(),
		"--output-path",
		fixture.manifest_borsh_path.to_str().unwrap(),
	]);
	assert_failure(&manifest_out);

	let envelope_out = run_qos_client([
		"json-to-borsh",
		"--display-type",
		"manifest-envelope",
		"--file-path",
		fixture.envelope_path.to_str().unwrap(),
		"--output-path",
		fixture.envelope_borsh_path.to_str().unwrap(),
	]);
	assert_failure(&envelope_out);
}

#[test]
fn v1_generate_manifest_without_patch_set_fails_cleanly() {
	let fixture = Fixture::new("v1_missing_patch_set");

	assert_success(&run_qos_client([
		"pivot-hash",
		"--output-path",
		fixture.pivot_hash_path.to_str().unwrap(),
		"--pivot-path",
		fixture.pivot_path.to_str().unwrap(),
	]));

	let output = run_qos_client([
		"generate-manifest",
		"--nonce",
		"31",
		"--namespace",
		"production/signer",
		"--restart-policy",
		"always",
		"--manifest-path",
		fixture.manifest_path.to_str().unwrap(),
		"--pivot-hash-path",
		fixture.pivot_hash_path.to_str().unwrap(),
		"--qos-release-dir",
		fixture.qos_release_dir.to_str().unwrap(),
		"--pcr3-preimage-path",
		fixture.pcr3_preimage_path.to_str().unwrap(),
		"--pivot-args",
		"[]",
		"--manifest-set-dir",
		fixture.manifest_set.to_str().unwrap(),
		"--share-set-dir",
		fixture.share_set.to_str().unwrap(),
		"--quorum-key-path",
		fixture.quorum_key_path.to_str().unwrap(),
	]);

	assert_failure(&output);
	let combined = format!(
		"{}{}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	);
	assert!(combined.contains("ManifestV1RequiresPatchSet"));
}

#[test]
fn v1_generate_manifest_with_dns_resolvers_fails_cleanly() {
	let fixture = Fixture::new("v1_dns_resolvers");

	assert_success(&run_qos_client([
		"pivot-hash",
		"--output-path",
		fixture.pivot_hash_path.to_str().unwrap(),
		"--pivot-path",
		fixture.pivot_path.to_str().unwrap(),
	]));

	let output = run_qos_client([
		"generate-manifest",
		"--nonce",
		"31",
		"--namespace",
		"production/signer",
		"--restart-policy",
		"always",
		"--manifest-path",
		fixture.manifest_path.to_str().unwrap(),
		"--pivot-hash-path",
		fixture.pivot_hash_path.to_str().unwrap(),
		"--qos-release-dir",
		fixture.qos_release_dir.to_str().unwrap(),
		"--pcr3-preimage-path",
		fixture.pcr3_preimage_path.to_str().unwrap(),
		"--pivot-args",
		"[]",
		"--manifest-set-dir",
		fixture.manifest_set.to_str().unwrap(),
		"--share-set-dir",
		fixture.share_set.to_str().unwrap(),
		"--quorum-key-path",
		fixture.quorum_key_path.to_str().unwrap(),
		"--dns-resolvers",
		"[1.1.1.1]",
	]);

	assert_failure(&output);
	let combined = format!(
		"{}{}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	);
	assert!(combined.contains("ManifestV1DoesNotSupportDnsConfig"));
}
