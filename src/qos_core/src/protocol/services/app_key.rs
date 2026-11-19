//! The app key: one key every enclave of a manifest shares, held only inside
//! those enclaves.
//!
//! A manifest opts in by naming an `app_key_minter`, a hybrid public key. Such
//! a manifest's enclaves do not pivot until they hold the app key. A boot that
//! has its quorum key (from shares, or from a key forward by an enclave of
//! another manifest) keeps it in memory and waits for one of two things:
//!
//! - a mint order: the minter's signature over [`app_key_mint_order_message`],
//!   which names this boot's setup ephemeral key, so an order mints on exactly
//!   one boot and a host cannot replay it to another;
//! - the app key itself, sealed by an attested enclave of the same manifest
//!   ([`app_key_transfer_user_data`]).
//!
//! A manifest that names no minter has no app key and pivots as soon as it has
//! its quorum key.
//!
//! A manifest that boots without a quorum key and names a minter waits the
//! same way straight after its manifest is approved, and pivots once it holds
//! the app key.

use qos_hybrid::{HybridPair, HybridPublic};
use qos_nsm::{
	nitro::ManifestAttestationInput,
	types::{NsmRequest, NsmResponse},
};
use sha2::{Digest as _, Sha512};
use zeroize::Zeroizing;

use crate::protocol::{
	ProtocolError, ProtocolState,
	services::key::{
		attested_ephemeral_key, verify_and_extract_attestation_doc_from_der,
	},
};

/// Domain separating [`app_key_transfer_user_data`].
const APP_KEY_TRANSFER_DOMAIN: &[u8] = b"qos_app_key_transfer_v1";
/// Domain separating [`app_key_mint_order_message`].
const APP_KEY_MINT_ORDER_DOMAIN: &[u8] = b"qos_app_key_mint_order_v1";

/// An app key sealed by an enclave to a waiting boot of the same manifest,
/// with the sender's attestation document binding the ciphertext: what
/// `qos_client export-app-key` writes and `inject-app-key` reads.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedAppKey {
	/// The app key's master seed encrypted to the waiting boot's setup
	/// Ephemeral Key.
	#[serde(with = "qos_hex::serde")]
	pub encrypted_app_key: Vec<u8>,
	/// The sender's COSE Sign1 attestation document, whose `user_data` is
	/// [`app_key_transfer_user_data`] over `encrypted_app_key`.
	#[serde(with = "qos_hex::serde")]
	pub app_key_attestation_doc: Vec<u8>,
}

/// Whether a step that obtained the quorum key also finished provisioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
	/// The keys are written and the pivot starts.
	Pivoting,
	/// The manifest names an app key minter and no app key came with the
	/// quorum key: the boot waits for a mint order or the forwarded app key.
	AwaitingAppKey,
}

/// The `user_data` an enclave attests when it seals the app key to another:
/// SHA-512 over a domain, the recipient's ephemeral key attestation binding
/// and the encrypted app key.
///
/// The quorum key's signature cannot vouch for the app key, because the
/// quorum key can be rebuilt outside an enclave from shares or a
/// disaster-recovery key; only an attested enclave can produce this binding.
#[must_use]
pub fn app_key_transfer_user_data(
	recipient_ephemeral_binding: &[u8],
	encrypted_app_key: &[u8],
) -> [u8; 64] {
	let mut hasher = Sha512::new();
	hasher.update(APP_KEY_TRANSFER_DOMAIN);
	hasher.update(recipient_ephemeral_binding);
	hasher.update(encrypted_app_key);
	hasher.finalize().into()
}

/// The message a manifest's app key minter signs to order one boot to mint:
/// a domain, the manifest hash and the boot's setup ephemeral key binding.
#[must_use]
pub fn app_key_mint_order_message(
	manifest_hash: &[u8],
	setup_ephemeral_binding: &[u8],
) -> Vec<u8> {
	let mut message = Vec::with_capacity(
		APP_KEY_MINT_ORDER_DOMAIN.len()
			+ manifest_hash.len()
			+ setup_ephemeral_binding.len(),
	);
	message.extend_from_slice(APP_KEY_MINT_ORDER_DOMAIN);
	message.extend_from_slice(manifest_hash);
	message.extend_from_slice(setup_ephemeral_binding);
	message
}

/// Finish provisioning with `quorum_pair`, or hold it until the app key
/// arrives.
///
/// `forwarded` is the encrypted app key and the sender's attestation document
/// that came with a key forward from an enclave of the same manifest.
pub(in crate::protocol) fn settle_quorum_key(
	state: &mut ProtocolState,
	quorum_pair: HybridPair,
	forwarded: Option<(Vec<u8>, Vec<u8>)>,
) -> Result<Settled, ProtocolError> {
	let names_minter =
		state.handles.get_manifest_envelope()?.app_key_minter().is_some();

	match (names_minter, forwarded) {
		(false, None) => {
			finish(state, Some(&quorum_pair), None)?;
			Ok(Settled::Pivoting)
		}
		(false, Some(_)) => Err(ProtocolError::AppKeyNotExpected),
		(true, Some((encrypted_app_key, attestation_doc))) => {
			let app_key =
				receive_app_key(state, &encrypted_app_key, &attestation_doc)?;
			finish(state, Some(&quorum_pair), Some(&app_key))?;
			Ok(Settled::Pivoting)
		}
		(true, None) => {
			state.set_pending_quorum_key(quorum_pair);
			Ok(Settled::AwaitingAppKey)
		}
	}
}

/// Mint the app key on this boot, as ordered by the manifest's minter.
///
/// # Errors
///
/// Refuses, leaving the boot waiting, when the manifest names no minter or the
/// order is not the minter's signature over this boot's
/// [`app_key_mint_order_message`].
pub(in crate::protocol) fn mint_app_key(
	state: &mut ProtocolState,
	order_signature: &[u8],
) -> Result<(), ProtocolError> {
	let manifest = state.handles.get_manifest_envelope()?.manifest();
	let minter =
		manifest.app_key_minter().ok_or(ProtocolError::AppKeyMinterNotNamed)?;
	let minter = HybridPublic::from_bytes(minter)
		.map_err(|_| ProtocolError::InvalidAppKeyMinter)?;
	let setup_binding =
		state.handles.get_ephemeral_key()?.public_key().attestation_binding();
	minter
		.verify(
			&app_key_mint_order_message(
				&manifest.manifest_hash(),
				&setup_binding,
			),
			order_signature,
		)
		.map_err(|_| ProtocolError::AppKeyMintOrderInvalid)?;

	let quorum_pair = take_quorum_key(state, manifest.no_quorum_key())?;
	finish(state, quorum_pair.as_ref(), Some(&HybridPair::generate()?))
}

/// Install the app key an attested enclave of this manifest sealed to this
/// boot.
///
/// # Errors
///
/// Refuses, leaving the boot waiting, when the sender's attestation does not
/// prove it runs this manifest and sealed exactly this ciphertext to this
/// boot.
pub(in crate::protocol) fn inject_app_key(
	state: &mut ProtocolState,
	encrypted_app_key: &[u8],
	attestation_doc: &[u8],
) -> Result<(), ProtocolError> {
	let app_key = receive_app_key(state, encrypted_app_key, attestation_doc)?;
	let no_quorum_key = state.handles.get_manifest_envelope()?.no_quorum_key();
	let quorum_pair = take_quorum_key(state, no_quorum_key)?;
	finish(state, quorum_pair.as_ref(), Some(&app_key))
}

/// The quorum key held waiting for the app key, or none for a manifest that
/// boots without one.
fn take_quorum_key(
	state: &mut ProtocolState,
	no_quorum_key: bool,
) -> Result<Option<HybridPair>, ProtocolError> {
	if no_quorum_key {
		Ok(None)
	} else {
		state.take_pending_quorum_key().map(Some)
	}
}

/// Seal this enclave's app key to a boot of the same manifest that is waiting
/// for it.
///
/// Returns the encrypted app key and this enclave's attestation document
/// binding it.
///
/// # Errors
///
/// Refuses when the requester's setup attestation does not prove it booted
/// this manifest with the ephemeral key it sent, or this enclave has no app
/// key.
pub(in crate::protocol) fn export_app_key(
	state: &ProtocolState,
	cose_sign1_attestation_doc: &[u8],
	ephemeral_public_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
	let attestation_doc = verify_and_extract_attestation_doc_from_der(
		cose_sign1_attestation_doc,
		&*state.attestor,
	)?;
	let manifest = state.handles.get_manifest_envelope()?.manifest();
	qos_nsm::nitro::verify_attestation_doc_against_manifest_setup(
		&attestation_doc,
		ManifestAttestationInput {
			manifest_hash: &manifest.manifest_hash(),
			pcr0: &manifest.enclave().pcr0,
			pcr1: &manifest.enclave().pcr1,
			pcr2: &manifest.enclave().pcr2,
			pcr3: &manifest.enclave().pcr3,
		},
	)?;
	let recipient =
		attested_ephemeral_key(&attestation_doc, ephemeral_public_key)?;
	seal_app_key(state, &recipient)
}

/// Encrypt the app key to `recipient` and attest the ciphertext.
///
/// Returns the encrypted app key and the COSE Sign1 attestation document
/// whose `user_data` binds it.
pub(in crate::protocol) fn seal_app_key(
	state: &ProtocolState,
	recipient: &HybridPublic,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
	let app_key = state.handles.get_app_key()?;
	let encrypted_app_key = recipient.encrypt(&app_key.to_master_seed()[..])?;
	let user_data = app_key_transfer_user_data(
		&recipient.attestation_binding(),
		&encrypted_app_key,
	);

	match state.attestor.nsm_process_request(NsmRequest::Attestation {
		user_data: Some(user_data.to_vec()),
		nonce: None,
		public_key: None,
	}) {
		NsmResponse::Attestation { document } => {
			Ok((encrypted_app_key, document))
		}
		response => Err(ProtocolError::QosAttestError(format!(
			"unexpected NSM response: {response:?}"
		))),
	}
}

/// Check that the sender's attestation proves it runs this enclave's manifest
/// and sealed exactly `encrypted_app_key` to this enclave, then decrypt it.
fn receive_app_key(
	state: &ProtocolState,
	encrypted_app_key: &[u8],
	cose_sign1_attestation_doc: &[u8],
) -> Result<HybridPair, ProtocolError> {
	let not_attested = |e: qos_nsm::nitro::AttestError| {
		ProtocolError::AppKeyTransferNotAttested(e.to_string())
	};
	let manifest = state.handles.get_manifest_envelope()?.manifest();
	let ephemeral_pair = state.handles.get_ephemeral_key()?;

	let attestation_doc = verify_and_extract_attestation_doc_from_der(
		cose_sign1_attestation_doc,
		&*state.attestor,
	)
	.map_err(|e| ProtocolError::AppKeyTransferNotAttested(e.to_string()))?;
	let user_data = app_key_transfer_user_data(
		&ephemeral_pair.public_key().attestation_binding(),
		encrypted_app_key,
	);
	qos_nsm::nitro::verify_attestation_doc_against_user_input(
		&attestation_doc,
		&user_data,
		&manifest.enclave().pcr0,
		&manifest.enclave().pcr1,
		&manifest.enclave().pcr2,
		&manifest.enclave().pcr3,
	)
	.map_err(not_attested)?;
	qos_nsm::nitro::verify_attestation_doc_manifest_only_commitment(
		&attestation_doc,
		&manifest.manifest_hash(),
	)
	.map_err(not_attested)?;

	let bytes = ephemeral_pair.decrypt(encrypted_app_key)?;
	let master_seed: Zeroizing<[u8; qos_hybrid::MASTER_SEED_LEN]> =
		Zeroizing::new(
			bytes[..]
				.try_into()
				.map_err(|_| ProtocolError::InvalidAppKeySecret)?,
		);
	HybridPair::from_master_seed(&master_seed)
		.map_err(|_| ProtocolError::InvalidAppKeySecret)
}

/// Rotate to the live ephemeral key, then write the app key, if any, and the
/// quorum key, if any. The last file written starts the pivot (see
/// `reaper.rs`).
fn finish(
	state: &mut ProtocolState,
	quorum_pair: Option<&HybridPair>,
	app_key: Option<&HybridPair>,
) -> Result<(), ProtocolError> {
	// The setup ephemeral key protected key delivery; apps get the live one.
	let live_ephemeral_key = state.take_pending_live_ephemeral_key()?;
	state.handles.rotate_ephemeral_key(&live_ephemeral_key)?;

	if let Some(app_key) = app_key {
		state.handles.put_app_key(app_key)?;
	}
	match quorum_pair {
		Some(quorum_pair) => state.handles.put_quorum_key(quorum_pair),
		None => Ok(()),
	}
}

#[cfg(test)]
mod test {
	use qos_hybrid::HybridPair;
	use qos_nsm::{
		NsmProvider,
		mock::MockNsm,
		nitro,
		types::{NsmRequest, NsmResponse},
	};
	use qos_test_primitives::PathWrapper;

	use super::{
		Settled, app_key_mint_order_message, app_key_transfer_user_data,
	};
	use crate::{
		handles::Handles,
		protocol::{
			ProtocolError, ProtocolPhase, ProtocolState,
			msg::{JsonBytes, ProtocolMsg},
			services::{
				app_key::{export_app_key, inject_app_key, mint_app_key},
				boot::{
					Approval, NitroConfig, PivotEnv, ShareSet,
					manifest::{
						ManifestVersion, VersionedManifestEnvelope,
						v2::{ManifestEnvelopeV2, ManifestV2, PivotConfigV2},
					},
				},
				key::{
					EncryptedQuorumKey, export_key, inject_key,
					test::{TestArgs, get_test_args},
				},
			},
		},
	};

	/// The test manifest as v2, approved by two members, naming `minter` as
	/// its app key minter, at `nonce`.
	fn v2_envelope(
		args: &TestArgs,
		minter: Option<&HybridPair>,
		nonce: u32,
	) -> VersionedManifestEnvelope {
		let v1 = &args.manifest_envelope.manifest;
		let mut namespace = v1.namespace.clone();
		namespace.nonce = nonce;
		let manifest = ManifestV2 {
			version: ManifestVersion::V2,
			namespace,
			pivot: PivotConfigV2 {
				hash: v1.pivot.hash,
				restart: v1.pivot.restart,
				bridge_config: v1.pivot.bridge_config.clone(),
				debug_mode: v1.pivot.debug_mode,
				args: v1.pivot.args.clone(),
				env: PivotEnv::default(),
			},
			manifest_set: v1.manifest_set.clone(),
			share_set: v1.share_set.clone(),
			enclave: v1.enclave.clone(),
			dns: None,
			app_key_minter: minter.map(|m| m.public_key().to_bytes()),
			no_quorum_key: false,
		};
		approved(args, manifest)
	}

	/// `manifest` as a v2 envelope approved by two members.
	fn approved(
		args: &TestArgs,
		manifest: ManifestV2,
	) -> VersionedManifestEnvelope {
		let unsigned = VersionedManifestEnvelope::V2(ManifestEnvelopeV2 {
			manifest: manifest.clone(),
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		});
		let hash = unsigned.manifest_hash();
		let manifest_set_approvals = args.members_with_keys[..2]
			.iter()
			.map(|(pair, member)| Approval {
				signature: pair.sign(&hash).unwrap(),
				member: member.clone(),
			})
			.collect();
		VersionedManifestEnvelope::V2(ManifestEnvelopeV2 {
			manifest,
			manifest_set_approvals,
			share_set_approvals: vec![],
		})
	}

	/// A mock NSM whose PCRs match `enclave`, and whose setup and
	/// manifest-only commitments are for `manifest_hash` and `eph_pair`.
	fn enclave_nsm(
		enclave: &NitroConfig,
		manifest_hash: &[u8],
		eph_pair: &HybridPair,
	) -> MockNsm {
		MockNsm::new()
			.with_pcr(0, enclave.pcr0.clone())
			.with_pcr(1, enclave.pcr1.clone())
			.with_pcr(2, enclave.pcr2.clone())
			.with_pcr(3, enclave.pcr3.clone())
			.with_pcr(
				nitro::SETUP_MANIFEST_COMMITMENT_PCR_INDEX,
				nitro::expected_manifest_commitment_pcr::<nitro::Setup>(
					manifest_hash,
					&eph_pair.public_key().attestation_binding(),
				)
				.unwrap()
				.to_vec(),
			)
			.with_pcr(
				nitro::MANIFEST_ONLY_COMMITMENT_PCR_INDEX,
				nitro::expected_manifest_only_commitment_pcr(manifest_hash)
					.unwrap()
					.to_vec(),
			)
	}

	/// The setup attestation a boot of `manifest_hash` with `eph_pair` returns.
	fn setup_document(
		nsm: &MockNsm,
		manifest_hash: &[u8],
		eph_pair: &HybridPair,
	) -> Vec<u8> {
		let NsmResponse::Attestation { document } =
			nsm.nsm_process_request(NsmRequest::Attestation {
				user_data: Some(manifest_hash.to_vec()),
				nonce: None,
				public_key: Some(
					eph_pair.public_key().attestation_binding().to_vec(),
				),
			})
		else {
			panic!("expected attestation response");
		};
		document
	}

	/// An enclave's files and state, removed on drop.
	struct Enclave {
		state: ProtocolState,
		_files: Vec<PathWrapper<String>>,
	}

	/// An enclave running `envelope` with ephemeral key `eph_pair`, holding
	/// `quorum_pair` and `app_pair` on disk when given, or waiting for them.
	fn enclave(
		name: &str,
		envelope: &VersionedManifestEnvelope,
		eph_pair: &HybridPair,
		nsm: MockNsm,
		held: Option<(&HybridPair, Option<&HybridPair>)>,
	) -> Enclave {
		let path = |file: &str| {
			PathWrapper::from(format!("/tmp/app_key_{name}.{file}"))
		};
		let files = vec![
			path("eph.secret"),
			path("quorum.secret"),
			path("app.secret"),
			path("manifest"),
		];
		eph_pair.to_hex_file(&*files[0]).unwrap();
		std::fs::write(&*files[3], envelope.to_storage_vec().unwrap()).unwrap();
		let handles = Handles::new(
			files[0].display().to_string(),
			files[1].display().to_string(),
			files[2].display().to_string(),
			files[3].display().to_string(),
			"pivot".to_string(),
		);
		if let Some((quorum_pair, app_pair)) = held {
			quorum_pair.to_hex_file(&*files[1]).unwrap();
			if let Some(app_pair) = app_pair {
				app_pair.to_hex_file(&*files[2]).unwrap();
			}
		}
		let mut state = ProtocolState::new(Box::new(nsm), handles, None);
		state.set_pending_live_ephemeral_key(HybridPair::generate().unwrap());
		Enclave { state, _files: files }
	}

	/// Forward the quorum key, and the app key when the manifests match, from
	/// an enclave running `source` to a New Node running `target`.
	fn forward(
		name: &str,
		args: &TestArgs,
		source: &VersionedManifestEnvelope,
		target: &VersionedManifestEnvelope,
		app_pair: Option<&HybridPair>,
	) -> EncryptedQuorumKey {
		let target_hash = target.manifest_hash();
		let nsm = enclave_nsm(target.enclave(), &target_hash, &args.eph_pair);
		let document = setup_document(&nsm, &target_hash, &args.eph_pair);
		let mut source_enclave = enclave(
			&format!("{name}_source"),
			source,
			&HybridPair::generate().unwrap(),
			nsm,
			Some((&args.quorum_pair, app_pair)),
		);
		export_key(
			&mut source_enclave.state,
			target.clone(),
			&document,
			&args.eph_pair.public_key().to_bytes(),
		)
		.unwrap()
	}

	fn sign_order(
		minter: &HybridPair,
		envelope: &VersionedManifestEnvelope,
		eph_pair: &HybridPair,
	) -> Vec<u8> {
		minter
			.sign(&app_key_mint_order_message(
				&envelope.manifest_hash(),
				&eph_pair.public_key().attestation_binding(),
			))
			.unwrap()
	}

	#[test]
	fn a_boot_of_a_manifest_without_a_minter_pivots_with_no_app_key() {
		let args = get_test_args();
		let envelope = v2_envelope(&args, None, 2);
		let forwarded = forward(
			"no_minter",
			&args,
			&v2_envelope(&args, None, 1),
			&envelope,
			None,
		);
		let mut receiver = enclave(
			"no_minter_receiver",
			&envelope,
			&args.eph_pair,
			MockNsm::new(),
			None,
		);

		assert_eq!(
			inject_key(&mut receiver.state, forwarded),
			Ok(Settled::Pivoting)
		);
		assert!(receiver.state.handles.quorum_key_exists());
		assert!(receiver.state.handles.get_app_key().is_err());
		assert_eq!(
			mint_app_key(&mut receiver.state, &[0; qos_hybrid::SIGNATURE_LEN]),
			Err(ProtocolError::AppKeyMinterNotNamed)
		);
	}

	#[test]
	fn a_forward_from_another_manifest_leaves_the_boot_waiting_for_the_app_key()
	{
		let args = get_test_args();
		let minter = HybridPair::generate().unwrap();
		let envelope = v2_envelope(&args, Some(&minter), 2);
		let forwarded = forward(
			"waits",
			&args,
			&v2_envelope(&args, Some(&minter), 1),
			&envelope,
			Some(&HybridPair::generate().unwrap()),
		);
		assert!(
			forwarded.encrypted_app_key.is_none(),
			"the app key never leaves for an enclave of another manifest"
		);
		let mut receiver = enclave(
			"waits_receiver",
			&envelope,
			&args.eph_pair,
			MockNsm::new(),
			None,
		);

		assert_eq!(
			inject_key(&mut receiver.state, forwarded),
			Ok(Settled::AwaitingAppKey)
		);
		assert!(
			!receiver.state.handles.quorum_key_exists(),
			"the quorum key file starts the pivot, so it waits for the app key"
		);
	}

	#[test]
	fn the_minters_order_mints_the_app_key_on_the_boot_it_names() {
		let args = get_test_args();
		let minter = HybridPair::generate().unwrap();
		let envelope = v2_envelope(&args, Some(&minter), 2);
		let mut receiver =
			enclave("mints", &envelope, &args.eph_pair, MockNsm::new(), None);
		receiver.state.set_pending_quorum_key(args.quorum_pair.clone());

		mint_app_key(
			&mut receiver.state,
			&sign_order(&minter, &envelope, &args.eph_pair),
		)
		.unwrap();

		assert!(receiver.state.handles.get_app_key().is_ok());
		assert!(receiver.state.handles.quorum_key_exists());
	}

	#[test]
	fn an_order_not_from_the_minter_or_for_another_boot_is_refused() {
		let args = get_test_args();
		let minter = HybridPair::generate().unwrap();
		let envelope = v2_envelope(&args, Some(&minter), 2);
		let mut receiver = enclave(
			"refuses_order",
			&envelope,
			&args.eph_pair,
			MockNsm::new(),
			None,
		);
		receiver.state.set_pending_quorum_key(args.quorum_pair.clone());

		for order in [
			sign_order(
				&HybridPair::generate().unwrap(),
				&envelope,
				&args.eph_pair,
			),
			sign_order(&minter, &envelope, &HybridPair::generate().unwrap()),
			sign_order(
				&minter,
				&v2_envelope(&args, Some(&minter), 3),
				&args.eph_pair,
			),
		] {
			assert_eq!(
				mint_app_key(&mut receiver.state, &order),
				Err(ProtocolError::AppKeyMintOrderInvalid),
				"only the minter's order for this manifest and this boot mints"
			);
		}
		assert!(receiver.state.handles.get_app_key().is_err());

		mint_app_key(
			&mut receiver.state,
			&sign_order(&minter, &envelope, &args.eph_pair),
		)
		.expect("a refused order leaves the boot waiting for a valid one");
	}

	#[test]
	fn a_same_manifest_forward_carries_the_app_key() {
		let args = get_test_args();
		let minter = HybridPair::generate().unwrap();
		let app_pair = HybridPair::generate().unwrap();
		let envelope = v2_envelope(&args, Some(&minter), 2);
		let forwarded =
			forward("carries", &args, &envelope, &envelope, Some(&app_pair));
		let encrypted = forwarded.encrypted_app_key.clone().unwrap();
		let attested = qos_nsm::nitro::unsafe_attestation_doc_from_der(
			forwarded.app_key_attestation_doc.as_ref().unwrap(),
		)
		.unwrap();
		assert_eq!(
			attested.user_data.unwrap().as_ref(),
			app_key_transfer_user_data(
				&args.eph_pair.public_key().attestation_binding(),
				&encrypted,
			)
			.as_slice()
		);
		let mut receiver = enclave(
			"carries_receiver",
			&envelope,
			&args.eph_pair,
			MockNsm::new(),
			None,
		);

		assert_eq!(
			inject_key(&mut receiver.state, forwarded),
			Ok(Settled::Pivoting)
		);
		assert!(receiver.state.handles.get_app_key().unwrap() == app_pair);
	}

	#[test]
	fn a_waiting_boot_receives_the_app_key_from_a_provisioned_peer() {
		let args = get_test_args();
		let minter = HybridPair::generate().unwrap();
		let app_pair = HybridPair::generate().unwrap();
		let envelope = v2_envelope(&args, Some(&minter), 2);
		let hash = envelope.manifest_hash();
		let nsm = enclave_nsm(envelope.enclave(), &hash, &args.eph_pair);
		let document = setup_document(&nsm, &hash, &args.eph_pair);
		let peer = enclave(
			"peer",
			&envelope,
			&HybridPair::generate().unwrap(),
			nsm,
			Some((&args.quorum_pair, Some(&app_pair))),
		);
		let (encrypted, attestation) = export_app_key(
			&peer.state,
			&document,
			&args.eph_pair.public_key().to_bytes(),
		)
		.unwrap();
		let mut waiting = enclave(
			"peer_waiting",
			&envelope,
			&args.eph_pair,
			MockNsm::new(),
			None,
		);
		waiting.state.set_pending_quorum_key(args.quorum_pair.clone());

		inject_app_key(&mut waiting.state, &encrypted, &attestation).unwrap();

		assert!(waiting.state.handles.get_app_key().unwrap() == app_pair);
		assert!(waiting.state.handles.quorum_key_exists());
	}

	#[test]
	fn a_peer_refuses_to_export_to_a_boot_of_another_manifest() {
		let args = get_test_args();
		let minter = HybridPair::generate().unwrap();
		let envelope = v2_envelope(&args, Some(&minter), 2);
		let other = v2_envelope(&args, Some(&minter), 3);
		let other_hash = other.manifest_hash();
		let nsm = enclave_nsm(other.enclave(), &other_hash, &args.eph_pair);
		let document = setup_document(&nsm, &other_hash, &args.eph_pair);
		let peer = enclave(
			"peer_refuses",
			&envelope,
			&HybridPair::generate().unwrap(),
			nsm,
			Some((&args.quorum_pair, Some(&HybridPair::generate().unwrap()))),
		);

		assert!(matches!(
			export_app_key(
				&peer.state,
				&document,
				&args.eph_pair.public_key().to_bytes()
			),
			Err(ProtocolError::QosAttestError(_))
		));
	}

	#[test]
	fn an_app_key_the_sender_did_not_attest_is_refused() {
		let args = get_test_args();
		let minter = HybridPair::generate().unwrap();
		let envelope = v2_envelope(&args, Some(&minter), 2);
		let mut forwarded = forward(
			"forged",
			&args,
			&envelope,
			&envelope,
			Some(&HybridPair::generate().unwrap()),
		);
		// Someone holding the quorum key, but not running in an enclave,
		// swaps in an app key they know.
		forwarded.encrypted_app_key = Some(
			args.eph_pair
				.public_key()
				.encrypt(&HybridPair::generate().unwrap().to_master_seed()[..])
				.unwrap(),
		);
		let mut receiver = enclave(
			"forged_receiver",
			&envelope,
			&args.eph_pair,
			MockNsm::new(),
			None,
		);

		assert!(matches!(
			inject_key(&mut receiver.state, forwarded),
			Err(ProtocolError::AppKeyTransferNotAttested(_))
		));
		assert!(!receiver.state.handles.quorum_key_exists());
	}

	#[test]
	fn the_state_machine_waits_for_the_app_key_and_retries_a_refused_order() {
		let args = get_test_args();
		let minter = HybridPair::generate().unwrap();
		let envelope = v2_envelope(&args, Some(&minter), 2);
		let EncryptedQuorumKey {
			encrypted_quorum_key,
			signature,
			encrypted_app_key,
			app_key_attestation_doc,
		} = forward(
			"phases",
			&args,
			&v2_envelope(&args, Some(&minter), 1),
			&envelope,
			None,
		);
		let mut receiver = enclave(
			"phases_receiver",
			&envelope,
			&args.eph_pair,
			MockNsm::new(),
			None,
		);
		receiver.state = ProtocolState::new(
			Box::new(MockNsm::new()),
			receiver.state.handles.clone(),
			Some(ProtocolPhase::WaitingForForwardedKey),
		);
		receiver
			.state
			.set_pending_live_ephemeral_key(HybridPair::generate().unwrap());

		assert_eq!(
			receiver.state.handle_msg_response(
				&ProtocolMsg::InjectKeyRequest {
					encrypted_quorum_key,
					signature,
					encrypted_app_key,
					app_key_attestation_doc,
				}
			),
			ProtocolMsg::InjectKeyResponse { awaiting_app_key: true }
		);
		assert_eq!(receiver.state.get_phase(), ProtocolPhase::WaitingForAppKey);

		let forged = sign_order(
			&HybridPair::generate().unwrap(),
			&envelope,
			&args.eph_pair,
		);
		assert_eq!(
			receiver.state.handle_msg_response(
				&ProtocolMsg::MintAppKeyRequest { order_signature: forged }
			),
			ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::AppKeyMintOrderInvalid
			)
		);
		assert_eq!(
			receiver.state.get_phase(),
			ProtocolPhase::WaitingForAppKey,
			"a refused order must not brick the boot"
		);

		assert_eq!(
			receiver.state.handle_msg_response(
				&ProtocolMsg::MintAppKeyRequest {
					order_signature: sign_order(
						&minter,
						&envelope,
						&args.eph_pair
					),
				}
			),
			ProtocolMsg::MintAppKeyResponse
		);
		assert_eq!(
			receiver.state.get_phase(),
			ProtocolPhase::QuorumKeyProvisioned
		);
		assert!(receiver.state.handles.quorum_key_exists());
	}

	/// [`v2_envelope`] made to boot without a quorum key: no quorum key in the
	/// namespace and an empty share set.
	fn no_quorum_key_envelope(
		args: &TestArgs,
		minter: Option<&HybridPair>,
		nonce: u32,
	) -> VersionedManifestEnvelope {
		let VersionedManifestEnvelope::V2(envelope) =
			v2_envelope(args, minter, nonce)
		else {
			unreachable!("v2_envelope builds v2");
		};
		let mut manifest = envelope.manifest;
		manifest.namespace.quorum_key = Vec::new();
		manifest.share_set = ShareSet { threshold: 0, members: Vec::new() };
		manifest.no_quorum_key = true;
		approved(args, manifest)
	}

	/// A fresh enclave waiting for its boot instruction, with files under
	/// `name`.
	fn unbooted(name: &str) -> Enclave {
		let path = |file: &str| {
			PathWrapper::from(format!("/tmp/app_key_{name}.{file}"))
		};
		let files = vec![
			path("eph.secret"),
			path("quorum.secret"),
			path("app.secret"),
			path("manifest"),
			path("pivot"),
		];
		let handles = Handles::new(
			files[0].display().to_string(),
			files[1].display().to_string(),
			files[2].display().to_string(),
			files[3].display().to_string(),
			files[4].display().to_string(),
		);
		let state = ProtocolState::new(Box::new(MockNsm::new()), handles, None);
		Enclave { state, _files: files }
	}

	/// Boot `envelope` on `enclave`, returning the setup ephemeral key the
	/// boot answered with.
	fn boot(
		enclave: &mut Enclave,
		envelope: &VersionedManifestEnvelope,
		pivot: &[u8],
	) -> Result<Vec<u8>, ProtocolMsg> {
		match enclave.state.handle_msg_response(
			&ProtocolMsg::BootStandardJsonEnvelopeRequest {
				manifest_envelope: Box::new(JsonBytes::new(envelope.clone())),
				pivot: pivot.to_vec(),
			},
		) {
			ProtocolMsg::BootStandardResponse {
				ephemeral_public_key, ..
			} => Ok(ephemeral_public_key),
			other => Err(other),
		}
	}

	#[test]
	fn a_manifest_without_a_quorum_key_runs_once_approved() {
		let args = get_test_args();
		let envelope = no_quorum_key_envelope(&args, None, 2);
		let mut booted = unbooted("no_quorum_runs");

		let setup_key = boot(&mut booted, &envelope, &args.pivot).unwrap();

		assert_eq!(
			booted.state.get_phase(),
			ProtocolPhase::BootedWithoutQuorumKey
		);
		assert!(!booted.state.handles.quorum_key_exists());
		assert!(!booted.state.handles.app_key_exists());
		assert_ne!(
			booted
				.state
				.handles
				.get_ephemeral_key()
				.unwrap()
				.public_key()
				.to_bytes(),
			setup_key,
			"the pivot starts on the live ephemeral key, not the setup key"
		);
		assert_ne!(
			booted.state.handle_msg_response(
				&ProtocolMsg::ExportAppKeyRequest {
					cose_sign1_attestation_doc: vec![],
					ephemeral_public_key: vec![],
				}
			),
			ProtocolMsg::ProtocolErrorResponse(ProtocolError::NoMatchingRoute(
				ProtocolPhase::BootedWithoutQuorumKey
			)),
			"a running enclave hands its app key to later replicas"
		);
	}

	#[test]
	fn a_manifest_without_a_quorum_key_runs_once_it_holds_its_app_key() {
		let args = get_test_args();
		let minter = HybridPair::generate().unwrap();
		let envelope = no_quorum_key_envelope(&args, Some(&minter), 2);
		let mut booted = unbooted("no_quorum_mints");

		let setup_key = boot(&mut booted, &envelope, &args.pivot).unwrap();
		assert_eq!(booted.state.get_phase(), ProtocolPhase::WaitingForAppKey);
		let setup_pair = booted.state.handles.get_ephemeral_key().unwrap();
		assert_eq!(setup_pair.public_key().to_bytes(), setup_key);

		assert_eq!(
			booted.state.handle_msg_response(&ProtocolMsg::MintAppKeyRequest {
				order_signature: sign_order(&minter, &envelope, &setup_pair),
			}),
			ProtocolMsg::MintAppKeyResponse
		);
		assert_eq!(
			booted.state.get_phase(),
			ProtocolPhase::BootedWithoutQuorumKey
		);
		assert!(booted.state.handles.app_key_exists());
		assert!(!booted.state.handles.quorum_key_exists());
		assert_ne!(
			booted
				.state
				.handles
				.get_ephemeral_key()
				.unwrap()
				.public_key()
				.to_bytes(),
			setup_key,
			"the setup ephemeral key is rotated out before the pivot starts"
		);
	}

	#[test]
	fn a_manifest_without_a_quorum_key_names_none_and_has_no_share_set() {
		let args = get_test_args();
		let VersionedManifestEnvelope::V2(envelope) =
			no_quorum_key_envelope(&args, None, 2)
		else {
			unreachable!("no_quorum_key_envelope builds v2");
		};

		let mut names_one = envelope.manifest.clone();
		names_one.namespace.quorum_key =
			args.quorum_pair.public_key().to_bytes();
		assert_eq!(
			boot(
				&mut unbooted("no_quorum_names_one"),
				&approved(&args, names_one),
				&args.pivot
			),
			Err(ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::NoQuorumKeyManifestNamesQuorumKey
			))
		);

		let mut has_share_set = envelope.manifest;
		has_share_set.share_set =
			args.manifest_envelope.manifest.share_set.clone();
		assert_eq!(
			boot(
				&mut unbooted("no_quorum_share_set"),
				&approved(&args, has_share_set),
				&args.pivot
			),
			Err(ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::NoQuorumKeyManifestHasShareSet
			))
		);
	}

	#[test]
	fn a_manifest_without_a_quorum_key_is_not_booted_by_key_forward() {
		let args = get_test_args();
		let envelope = no_quorum_key_envelope(&args, None, 2);
		let mut booted = unbooted("no_quorum_forward");

		assert_eq!(
			booted.state.handle_msg_response(
				&ProtocolMsg::BootKeyForwardRequest {
					manifest_envelope: Box::new(envelope),
					pivot: args.pivot.clone(),
				}
			),
			ProtocolMsg::ProtocolErrorResponse(
				ProtocolError::NoQuorumKeyToForward
			)
		);
	}
}
