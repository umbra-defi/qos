//! Quorum protocol state machine
use qos_hybrid::HybridPair;
use qos_nsm::NsmProvider;

use super::{
	error::ProtocolError, msg::ProtocolMsg, services::provision::SecretBuilder,
};
use crate::handles::Handles;

/// Enclave phase
#[derive(
	Debug,
	Copy,
	PartialEq,
	Eq,
	Clone,
	borsh::BorshSerialize,
	borsh::BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
pub enum ProtocolPhase {
	// Keep legacy PascalCase wire values for backward compatibility with
	// existing clients, while accepting camelCase aliases during decode.
	/// The state machine cannot recover. The enclave must be rebooted.
	#[serde(rename = "UnrecoverableError", alias = "unrecoverableError")]
	UnrecoverableError,
	/// Waiting to receive a boot instruction.
	#[serde(
		rename = "WaitingForBootInstruction",
		alias = "waitingForBootInstruction"
	)]
	WaitingForBootInstruction,
	/// Genesis service has been booted. No further actions.
	#[serde(rename = "GenesisBooted", alias = "genesisBooted")]
	GenesisBooted,
	/// Waiting to receive K quorum shards
	#[serde(
		rename = "WaitingForQuorumShards",
		alias = "waitingForQuorumShards"
	)]
	WaitingForQuorumShards,
	/// The enclave has successfully provisioned its quorum key.
	#[serde(rename = "QuorumKeyProvisioned", alias = "quorumKeyProvisioned")]
	QuorumKeyProvisioned,
	/// Waiting for a forwarded key to be injected
	#[serde(
		rename = "WaitingForForwardedKey",
		alias = "waitingForForwardedKey"
	)]
	WaitingForForwardedKey,
	/// Holding the quorum key, unwritten, until the app key is minted by the
	/// manifest minter's order or forwarded by an enclave of the manifest.
	#[serde(rename = "WaitingForAppKey", alias = "waitingForAppKey")]
	WaitingForAppKey,
}

/// Enclave routes
type ProtocolRouteResponse = Option<Result<ProtocolMsg, ProtocolMsg>>;
type ProtocolRouteHandler =
	dyn Fn(&ProtocolMsg, &mut ProtocolState) -> ProtocolRouteResponse;

struct ProtocolRoute {
	handler: Box<ProtocolRouteHandler>,
	ok_phase: ProtocolPhase, // the next phase if handler() == Ok
	err_phase: ProtocolPhase, // the next phase if handler() == Err
}

impl ProtocolRoute {
	pub fn try_msg(
		&self,
		msg: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		let resp = (self.handler)(msg, state);

		// ignore transitions in special cases
		if let Some(Ok(ProtocolMsg::ProvisionResponse {
			reconstructed: false,
			..
		})) = resp
		{
			return resp;
		}

		// handle state transitions
		let transition = match resp {
			None => None,
			Some(ref result) => match result {
				Ok(
					ProtocolMsg::ProvisionResponse {
						awaiting_app_key: true,
						..
					}
					| ProtocolMsg::InjectKeyResponse { awaiting_app_key: true },
				) => Some(ProtocolPhase::WaitingForAppKey),
				Ok(_) => Some(self.ok_phase),
				Err(_) => Some(self.err_phase),
			},
		};

		if let Some(phase) = transition
			&& let Err(e) = state.transition(phase)
		{
			return Some(Err(ProtocolMsg::ProtocolErrorResponse(e)));
		}

		resp
	}

	pub fn status(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::status),
			current_phase,
			current_phase,
		)
	}

	pub fn version(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::version),
			current_phase,
			current_phase,
		)
	}

	pub fn manifest_envelope(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::manifest_envelope),
			current_phase,
			current_phase,
		)
	}

	pub fn live_attestation_doc(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::live_attestation_doc),
			current_phase,
			current_phase,
		)
	}

	pub fn boot_genesis(_current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::boot_genesis),
			ProtocolPhase::GenesisBooted,
			ProtocolPhase::UnrecoverableError,
		)
	}

	pub fn boot_standard(_current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::boot_standard),
			ProtocolPhase::WaitingForQuorumShards,
			ProtocolPhase::UnrecoverableError,
		)
	}

	pub fn boot_key_forward(_current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::boot_key_forward),
			ProtocolPhase::WaitingForForwardedKey,
			ProtocolPhase::UnrecoverableError,
		)
	}

	pub fn provision(_current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::provision),
			ProtocolPhase::QuorumKeyProvisioned,
			ProtocolPhase::UnrecoverableError,
		)
	}

	pub fn export_key(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::export_key),
			current_phase,
			current_phase,
		)
	}

	pub fn inject_key(_current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::inject_key),
			ProtocolPhase::QuorumKeyProvisioned,
			ProtocolPhase::UnrecoverableError,
		)
	}

	// A refused order or app key leaves the boot waiting, so the next one can
	// be sent.
	pub fn mint_app_key(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::mint_app_key),
			ProtocolPhase::QuorumKeyProvisioned,
			current_phase,
		)
	}

	pub fn inject_app_key(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::inject_app_key),
			ProtocolPhase::QuorumKeyProvisioned,
			current_phase,
		)
	}

	pub fn export_app_key(current_phase: ProtocolPhase) -> Self {
		ProtocolRoute::new(
			Box::new(handlers::export_app_key),
			current_phase,
			current_phase,
		)
	}

	fn new(
		handler: Box<ProtocolRouteHandler>,
		ok_phase: ProtocolPhase,
		err_phase: ProtocolPhase,
	) -> Self {
		ProtocolRoute { handler, ok_phase, err_phase }
	}
}

/// Enclave state
pub(crate) struct ProtocolState {
	pub provisioner: SecretBuilder,
	pub attestor: Box<dyn NsmProvider>,
	pub handles: Handles,
	pending_live_ephemeral_key: Option<HybridPair>,
	pending_quorum_key: Option<HybridPair>,
	phase: ProtocolPhase,
}

impl ProtocolState {
	pub fn new(
		attestor: Box<dyn NsmProvider>,
		handles: Handles,
		#[allow(unused)] test_only_init_phase_override: Option<ProtocolPhase>,
	) -> Self {
		let provisioner = SecretBuilder::new();

		#[cfg(any(feature = "mock", test))]
		let init_phase = if let Some(phase) = test_only_init_phase_override {
			phase
		} else {
			ProtocolPhase::WaitingForBootInstruction
		};
		#[cfg(not(any(feature = "mock", test)))]
		let init_phase = ProtocolPhase::WaitingForBootInstruction;

		Self {
			attestor,
			provisioner,
			pending_live_ephemeral_key: None,
			pending_quorum_key: None,
			phase: init_phase,
			handles,
		}
	}

	pub fn get_phase(&self) -> ProtocolPhase {
		self.phase
	}

	pub(crate) fn set_pending_live_ephemeral_key(&mut self, key: HybridPair) {
		self.pending_live_ephemeral_key = Some(key);
	}

	pub(crate) fn take_pending_live_ephemeral_key(
		&mut self,
	) -> Result<HybridPair, ProtocolError> {
		self.pending_live_ephemeral_key
			.take()
			.ok_or(ProtocolError::MissingLiveEphemeralKey)
	}

	pub(crate) fn set_pending_quorum_key(&mut self, key: HybridPair) {
		self.pending_quorum_key = Some(key);
	}

	pub(crate) fn take_pending_quorum_key(
		&mut self,
	) -> Result<HybridPair, ProtocolError> {
		self.pending_quorum_key
			.take()
			.ok_or(ProtocolError::MissingPendingQuorumKey)
	}

	pub fn handle_msg_response(
		&mut self,
		msg_req: &ProtocolMsg,
	) -> ProtocolMsg {
		for route in &self.routes() {
			match route.try_msg(msg_req, self) {
				None => (),
				Some(result) => match result {
					Ok(msg_resp) | Err(msg_resp) => {
						return msg_resp;
					}
				},
			}
		}

		let err = ProtocolError::NoMatchingRoute(self.phase);
		ProtocolMsg::ProtocolErrorResponse(err)
	}

	#[allow(clippy::too_many_lines)]
	fn routes(&self) -> Vec<ProtocolRoute> {
		#[allow(clippy::match_same_arms)]
		match self.phase {
			ProtocolPhase::UnrecoverableError => {
				vec![
					ProtocolRoute::status(self.phase),
					ProtocolRoute::version(self.phase),
					ProtocolRoute::manifest_envelope(self.phase),
					ProtocolRoute::live_attestation_doc(self.phase),
				]
			}
			ProtocolPhase::GenesisBooted => {
				vec![
					ProtocolRoute::status(self.phase),
					ProtocolRoute::version(self.phase),
				]
			}
			ProtocolPhase::WaitingForBootInstruction => vec![
				// baseline routes
				ProtocolRoute::status(self.phase),
				ProtocolRoute::version(self.phase),
				ProtocolRoute::manifest_envelope(self.phase),
				// phase specific routes
				ProtocolRoute::boot_genesis(self.phase),
				ProtocolRoute::boot_standard(self.phase),
				ProtocolRoute::boot_key_forward(self.phase),
			],
			ProtocolPhase::WaitingForQuorumShards => {
				vec![
					// baseline routes
					ProtocolRoute::status(self.phase),
					ProtocolRoute::version(self.phase),
					ProtocolRoute::live_attestation_doc(self.phase),
					ProtocolRoute::manifest_envelope(self.phase),
					// phase specific routes
					ProtocolRoute::provision(self.phase),
				]
			}
			ProtocolPhase::QuorumKeyProvisioned => {
				vec![
					// baseline routes
					ProtocolRoute::status(self.phase),
					ProtocolRoute::version(self.phase),
					ProtocolRoute::live_attestation_doc(self.phase),
					ProtocolRoute::manifest_envelope(self.phase),
					// phase specific routes
					ProtocolRoute::export_key(self.phase),
					ProtocolRoute::export_app_key(self.phase),
				]
			}
			ProtocolPhase::WaitingForForwardedKey => {
				vec![
					// baseline routes
					ProtocolRoute::status(self.phase),
					ProtocolRoute::version(self.phase),
					ProtocolRoute::live_attestation_doc(self.phase),
					ProtocolRoute::manifest_envelope(self.phase),
					// phase specific routes
					ProtocolRoute::inject_key(self.phase),
				]
			}
			ProtocolPhase::WaitingForAppKey => {
				vec![
					// baseline routes
					ProtocolRoute::status(self.phase),
					ProtocolRoute::version(self.phase),
					ProtocolRoute::live_attestation_doc(self.phase),
					ProtocolRoute::manifest_envelope(self.phase),
					// phase specific routes
					ProtocolRoute::mint_app_key(self.phase),
					ProtocolRoute::inject_app_key(self.phase),
				]
			}
		}
	}

	pub fn transition(
		&mut self,
		next: ProtocolPhase,
	) -> Result<(), ProtocolError> {
		if self.phase == next {
			return Ok(());
		}

		#[allow(clippy::match_same_arms)]
		let transitions = match self.phase {
			ProtocolPhase::UnrecoverableError => vec![],
			ProtocolPhase::WaitingForBootInstruction => vec![
				ProtocolPhase::UnrecoverableError,
				ProtocolPhase::GenesisBooted,
				ProtocolPhase::WaitingForQuorumShards,
				ProtocolPhase::WaitingForForwardedKey,
			],
			ProtocolPhase::GenesisBooted => {
				vec![ProtocolPhase::UnrecoverableError]
			}
			ProtocolPhase::WaitingForQuorumShards => {
				vec![
					ProtocolPhase::UnrecoverableError,
					ProtocolPhase::QuorumKeyProvisioned,
					ProtocolPhase::WaitingForAppKey,
				]
			}
			ProtocolPhase::QuorumKeyProvisioned => {
				vec![ProtocolPhase::UnrecoverableError]
			}
			ProtocolPhase::WaitingForForwardedKey => {
				vec![
					ProtocolPhase::UnrecoverableError,
					ProtocolPhase::QuorumKeyProvisioned,
					ProtocolPhase::WaitingForAppKey,
				]
			}
			ProtocolPhase::WaitingForAppKey => {
				vec![
					ProtocolPhase::UnrecoverableError,
					ProtocolPhase::QuorumKeyProvisioned,
				]
			}
		};

		if !transitions.contains(&next) {
			let prev = self.phase;
			self.phase = ProtocolPhase::UnrecoverableError;
			return Err(ProtocolError::InvalidStateTransition(prev, next));
		}

		self.phase = next;
		Ok(())
	}
}

mod handlers {
	use super::ProtocolRouteResponse;
	use crate::protocol::{
		ProtocolState,
		msg::ProtocolMsg,
		services::{
			app_key, app_key::Settled, attestation, boot, genesis, key,
			key::EncryptedQuorumKey, provision,
		},
	};

	// TODO: Add tests for this in the middle of some integration tests
	/// Status of the enclave.
	pub(super) fn status(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::StatusRequest = req {
			Some(Ok(ProtocolMsg::StatusResponse(state.get_phase())))
		} else {
			None
		}
	}

	/// QOS version and git commit of the running enclave. Captured at
	/// compile time — `CARGO_PKG_VERSION` for the version, and the
	/// `QOS_GIT_COMMIT` env var (set by `build.rs`) for the commit.
	pub(super) fn version(
		req: &ProtocolMsg,
		_state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::VersionRequest = req {
			Some(Ok(ProtocolMsg::VersionResponse {
				version: env!("CARGO_PKG_VERSION").to_string(),
				commit: env!("QOS_GIT_COMMIT").to_string(),
			}))
		} else {
			None
		}
	}

	pub(super) fn manifest_envelope(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::ManifestEnvelopeRequest = req {
			Some(Ok(ProtocolMsg::ManifestEnvelopeResponse {
				manifest_envelope: Box::new(
					state.handles.get_manifest_envelope().ok(),
				),
			}))
		} else {
			None
		}
	}

	pub(super) fn provision(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::ProvisionRequest { share, approval } = req {
			let result = provision::provision(share, approval.clone(), state)
				.map(|settled| ProtocolMsg::ProvisionResponse {
					reconstructed: settled.is_some(),
					awaiting_app_key: settled == Some(Settled::AwaitingAppKey),
				})
				.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}

	/// Handle `ProtocolMsg::BootStandardRequest`.
	pub(super) fn boot_standard(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		let (manifest_envelope, pivot) = match req {
			ProtocolMsg::BootStandardRequest { manifest_envelope, pivot } => {
				((**manifest_envelope).clone(), pivot)
			}
			ProtocolMsg::BootStandardJsonEnvelopeRequest {
				manifest_envelope,
				pivot,
			} => (manifest_envelope.as_ref().clone().into_inner(), pivot),
			_ => return None,
		};

		let result = boot::boot_standard(state, manifest_envelope, pivot)
			.map(|(nsm_response, ephemeral_public_key)| {
				ProtocolMsg::BootStandardResponse {
					nsm_response,
					ephemeral_public_key,
				}
			})
			.map_err(ProtocolMsg::ProtocolErrorResponse);

		Some(result)
	}

	pub(super) fn boot_genesis(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::BootGenesisRequest { set, dr_key } = req {
			let result = genesis::boot_genesis(state, set, dr_key.clone())
				.map(|(genesis_output, nsm_response)| {
					ProtocolMsg::BootGenesisResponse {
						nsm_response,
						genesis_output: Box::new(genesis_output),
					}
				})
				.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn live_attestation_doc(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::LiveAttestationDocRequest = req {
			let result = attestation::live_attestation_doc(state)
				.map(|(nsm_response, ephemeral_public_key)| {
					ProtocolMsg::LiveAttestationDocResponse {
						nsm_response,
						ephemeral_public_key,
						manifest_envelope: state
							.handles
							.get_manifest_envelope()
							.ok()
							.map(Box::new),
					}
				})
				.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn boot_key_forward(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::BootKeyForwardRequest { manifest_envelope, pivot } =
			req
		{
			let result = key::boot_key_forward(state, manifest_envelope, pivot)
				.map(|(nsm_response, ephemeral_public_key)| {
					ProtocolMsg::BootKeyForwardResponse {
						nsm_response,
						ephemeral_public_key,
					}
				})
				.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn export_key(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::ExportKeyRequest {
			manifest_envelope,
			cose_sign1_attestation_doc,
			ephemeral_public_key,
		} = req
		{
			let result = key::export_key(
				state,
				manifest_envelope,
				cose_sign1_attestation_doc,
				ephemeral_public_key,
			)
			.map(|key| {
				let EncryptedQuorumKey {
					encrypted_quorum_key,
					signature,
					encrypted_app_key,
					app_key_attestation_doc,
				} = key;
				ProtocolMsg::ExportKeyResponse {
					encrypted_quorum_key,
					signature,
					encrypted_app_key,
					app_key_attestation_doc,
				}
			})
			.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn inject_key(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::InjectKeyRequest {
			encrypted_quorum_key,
			signature,
			encrypted_app_key,
			app_key_attestation_doc,
		} = req
		{
			let result = key::inject_key(
				state,
				EncryptedQuorumKey {
					encrypted_quorum_key: encrypted_quorum_key.clone(),
					signature: signature.clone(),
					encrypted_app_key: encrypted_app_key.clone(),
					app_key_attestation_doc: app_key_attestation_doc.clone(),
				},
			)
			.map(|settled| ProtocolMsg::InjectKeyResponse {
				awaiting_app_key: settled == Settled::AwaitingAppKey,
			})
			.map_err(ProtocolMsg::ProtocolErrorResponse);

			Some(result)
		} else {
			None
		}
	}

	pub(super) fn mint_app_key(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::MintAppKeyRequest { order_signature } = req {
			Some(
				app_key::mint_app_key(state, order_signature)
					.map(|()| ProtocolMsg::MintAppKeyResponse)
					.map_err(ProtocolMsg::ProtocolErrorResponse),
			)
		} else {
			None
		}
	}

	pub(super) fn inject_app_key(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::InjectAppKeyRequest {
			encrypted_app_key,
			app_key_attestation_doc,
		} = req
		{
			Some(
				app_key::inject_app_key(
					state,
					encrypted_app_key,
					app_key_attestation_doc,
				)
				.map(|()| ProtocolMsg::InjectAppKeyResponse)
				.map_err(ProtocolMsg::ProtocolErrorResponse),
			)
		} else {
			None
		}
	}

	pub(super) fn export_app_key(
		req: &ProtocolMsg,
		state: &mut ProtocolState,
	) -> ProtocolRouteResponse {
		if let ProtocolMsg::ExportAppKeyRequest {
			cose_sign1_attestation_doc,
			ephemeral_public_key,
		} = req
		{
			Some(
				app_key::export_app_key(
					state,
					cose_sign1_attestation_doc,
					ephemeral_public_key,
				)
				.map(|(encrypted_app_key, app_key_attestation_doc)| {
					ProtocolMsg::ExportAppKeyResponse {
						encrypted_app_key,
						app_key_attestation_doc,
					}
				})
				.map_err(ProtocolMsg::ProtocolErrorResponse),
			)
		} else {
			None
		}
	}
}
