//! Quorum protocol error
use borsh::{BorshDeserialize, BorshSerialize};
use qos_hybrid::HybridError;

use crate::{
	client::ClientError,
	io::IOError,
	protocol::{ProtocolPhase, services::boot},
};

/// A error from protocol execution.
#[derive(
	Debug,
	Clone,
	PartialEq,
	Eq,
	BorshSerialize,
	BorshDeserialize,
	serde::Serialize,
	serde::Deserialize,
)]
#[non_exhaustive]
pub enum ProtocolError {
	/// A encrypted quorum key share sent to the enclave was invalid.
	InvalidShare,
	/// Failed to reconstruct the quorum key while provisioning.
	ReconstructionErrorEmptySecret,
	/// Reconstructed the incorrect key while provisioning.
	ReconstructionErrorIncorrectPubKey,
	/// Filesystem error
	IOError,
	/// Cryptography error
	/// Approval was not valid for a manifest.
	InvalidManifestApproval(boot::Approval),
	/// [`boot::ManifestEnvelope`] did not have approvals
	NotEnoughApprovals,
	/// Protocol Message could not be matched against an available route.
	/// Ensure the executor is in the correct phase.
	NoMatchingRoute(ProtocolPhase),
	/// Hash of the Pivot binary does not match the pivot configuration in the
	/// manifest.
	InvalidPivotHash {
		/// Expected hash as hex string.
		expected: String,
		/// Actual hash as hex string.
		actual: String,
	},
	/// The message is too large.
	OversizeMsg,
	/// Message could not be deserialized
	InvalidMsg,
	/// An error occurred with the enclave client.
	EnclaveClient,
	/// Failed attempting to decrypt something.
	DecryptionFailed,
	/// Could not create a private key.
	InvalidPrivateKey,
	/// Failed to parse from string.
	FailedToParseFromString,
	/// Got a path to a key that is used for testing. This error only occurs
	/// when the "mock" feature is disabled, which should always be the
	/// case in production.
	BadEphemeralKeyPath,
	/// Tried to modify state that must be static post pivoting.
	CannotModifyPostPivotStatic,
	/// For some reason the Ephemeral could not be read from the file
	/// system.
	FailedToGetEphemeralKey(HybridError),
	/// Failed to write the Ephemeral key to the file system.
	FailedToPutEphemeralKey,
	/// Failed to rotate the ephemeral key because the underlying file is missing.
	CannotRotateNonExistentEphemeralKey,
	/// Failed to delete the old ephemeral key (underlying failure in argument)
	CannotDeleteEphemeralKey(String),
	/// For some reason the Quorum Key could not be read from the file
	/// system.
	FailedToGetQuorumKey(HybridError),
	/// Failed to put the quorum key into the file system
	FailedToPutQuorumKey,
	/// For some reason the manifest envelope could not be read from the file
	/// system or decoded.
	FailedToGetManifestEnvelope,
	/// Failed to put the manifest envelope.
	FailedToPutManifestEnvelope,
	/// Failed to put the pivot executable.
	FailedToPutPivot,
	/// The socket client timed out while waiting to receive a response from
	/// the enclave app.
	AppClientRecvTimeout,
	/// The socket client was interrupted while trying to receive a response
	/// from the enclave app.
	AppClientRecvInterrupted,
	/// The socket client tried to call receive on a closed connection. Likely
	/// the enclave app panicked and closed the connection.
	AppClientRecvConnectionClosed,
	/// App client could not make a connection to a socket when trying to send.
	/// Likely the enclave app panic'ed and the apps server did not create the
	/// socket again.
	AppClientConnectError(String),
	/// App client encountered an error when calling the `send` system call.
	AppClientSendError(String),
	/// The socket client encountered an error when trying to execute a request
	/// to the enclave app.
	AppClientError(String),
	/// Payload is too big. See `MAX_ENCODED_MSG_LEN` for the upper bound on
	/// message size.
	OversizedPayload,
	/// A protocol message could not be deserialized.
	ProtocolMsgDeserialization,
	/// Share set approvals existed in the manifest envelope when they should
	/// not have.
	BadShareSetApprovals,
	/// Could not verify a message against an approval
	CouldNotVerifyApproval,
	/// Not a member of the [`boot::ShareSet`].
	NotShareSetMember,
	/// Not a member of the [`boot::ManifestSet`].
	NotManifestSetMember,
	/// `qos_hybrid` Error wrapper.
	HybridError(qos_hybrid::HybridError),
	/// Error with trying to read the hybrid DR public key.
	InvalidDRKey(qos_hybrid::HybridError),
	/// The provisioned secret is the incorrect length.
	IncorrectSecretLen,
	/// An error from the attest crate.
	QosAttestError(String),
	/// Quorum Key in the new manifest does not match the quorum key in the old
	/// manifest.
	DifferentQuorumKey {
		/// Expected value as hex string.
		expected: String,
		/// Actual value as hex string.
		actual: String,
	},
	/// The manifest sets do not match.
	DifferentManifestSet {
		/// Expected hash as hex string.
		expected: String,
		/// Actual hash as hex string.
		actual: String,
	},
	/// The manifests do not have the same namespace names.
	DifferentNamespaceName {
		/// Expected namespace name.
		expected: String,
		/// Actual namespace name.
		actual: String,
	},
	/// The manifest has a lower nonce then the current manifest.
	LowNonce {
		/// Expected minimum nonce value.
		#[serde(with = "qos_json::string_or_numeric")]
		expected: u32,
		/// Actual nonce value.
		#[serde(with = "qos_json::string_or_numeric")]
		actual: u32,
	},
	/// The manifests have different PCR3 values.
	DifferentPcr3 {
		/// Expected value as hex string.
		expected: String,
		/// Actual value as hex string.
		actual: String,
	},
	/// Attestation document is missing ephemeral key.
	MissingEphemeralKey,
	/// Ephemeral key cannot be decoded.
	InvalidEphemeralKey,
	/// Invalid signature over the encrypted quorum key.
	InvalidEncryptedQuorumKeySignature,
	/// Invalid length for encrypted quorum key secret.
	EncryptedQuorumKeyInvalidLen,
	/// The quorum secret was invalid.
	InvalidQuorumSecret,
	/// The injected quorum key was not the expected key.
	WrongQuorumKey,
	/// State machine transitioned unexpectedly
	InvalidStateTransition(ProtocolPhase, ProtocolPhase),
	/// The manifest envelope has duplicate approvals.
	DuplicateApproval,
	/// The new manifest was different from the old manifest when we expected
	/// them to be the same because they have the same nonce.
	DifferentManifest {
		/// Expected hash as hex string.
		expected: String,
		/// Actual hash as hex string.
		actual: String,
	},
	/// Error from the qos crypto library.
	QosCrypto(String),
	/// Error during expanding the `StreamPool`.
	PoolExpandError,
	/// Pivot environment variables are invalid.
	InvalidPivotEnv(String),
	/// The precommitted live ephemeral key is missing from protocol state.
	MissingLiveEphemeralKey,
	/// A set of quorum members contains the same alias, signing public key,
	/// or encryption public key more than once.
	DuplicateQuorumMember,
	/// Genesis messages are only supported on the canonical JSON wire
	/// encoding; legacy Borsh genesis is not supported.
	LegacyGenesisNotSupported,
	/// The ephemeral key does not match the attestation binding in the
	/// attestation document's `public_key` field.
	EphemeralKeyNotAttested,
	/// Failed to read the app key.
	FailedToGetAppKey(HybridError),
	/// Failed to write the app key.
	FailedToPutAppKey,
	/// The forwarded key carried an encrypted app key without the sending
	/// enclave's attestation, or the reverse.
	AppKeyTransferIncomplete,
	/// The sending enclave's attestation does not prove it runs this
	/// enclave's manifest and sealed this exact app key to this enclave.
	AppKeyTransferNotAttested(String),
	/// The decrypted app key is not a master seed.
	InvalidAppKeySecret,
	/// An app key was forwarded for a manifest that names no app key minter.
	AppKeyNotExpected,
	/// A mint order was sent for a manifest that names no app key minter.
	AppKeyMinterNotNamed,
	/// The manifest's app key minter is not a hybrid public key.
	InvalidAppKeyMinter,
	/// The mint order is not the minter's signature for this manifest and
	/// this boot's setup ephemeral key.
	AppKeyMintOrderInvalid,
	/// No quorum key is held waiting for the app key.
	MissingPendingQuorumKey,
	/// A manifest that boots without a quorum key names one in its namespace.
	NoQuorumKeyManifestNamesQuorumKey,
	/// A manifest that boots without a quorum key has a share set.
	NoQuorumKeyManifestHasShareSet,
	/// A key forward boot was sent a manifest that has no quorum key to
	/// forward.
	NoQuorumKeyToForward,
	/// The share set or genesis set is not a valid share tree.
	InvalidShareTree(String),
	/// The member already provisioned a share for this boot.
	ShareAlreadyProvisioned,
	/// The posted shard is not an envelope key shard.
	ShareNotForMember,
	/// The quorum key envelope is malformed, is not the one the manifest names, or does not
	/// open.
	QuorumKeyEnvelope(String),
	/// A shard was posted before the quorum key envelope the manifest names.
	QuorumKeyEnvelopeNotProvided,
	/// A reshare's approvals do not sign it, or do not satisfy both the current holder tree and
	/// the manifest set.
	ReshareNotApproved(String),
}

impl From<std::io::Error> for ProtocolError {
	fn from(_err: std::io::Error) -> Self {
		Self::IOError
	}
}

impl From<ClientError> for ProtocolError {
	fn from(err: ClientError) -> Self {
		match err {
			ClientError::IOError(IOError::RecvTimeout) => {
				ProtocolError::AppClientRecvTimeout
			}
			ClientError::IOError(IOError::RecvInterrupted) => {
				ProtocolError::AppClientRecvInterrupted
			}
			ClientError::IOError(IOError::RecvConnectionClosed) => {
				ProtocolError::AppClientRecvConnectionClosed
			}
			ClientError::IOError(IOError::ConnectNixError(e)) => {
				ProtocolError::AppClientConnectError(format!("{e:?}"))
			}
			ClientError::IOError(IOError::SendNixError(e)) => {
				ProtocolError::AppClientSendError(format!("{e:?}"))
			}
			e => ProtocolError::AppClientError(format!("{e:?}")),
		}
	}
}

impl From<qos_hybrid::HybridError> for ProtocolError {
	fn from(err: qos_hybrid::HybridError) -> Self {
		Self::HybridError(err)
	}
}

impl From<qos_nsm::nitro::AttestError> for ProtocolError {
	fn from(err: qos_nsm::nitro::AttestError) -> Self {
		let msg = format!("{err:?}");
		Self::QosAttestError(msg)
	}
}

impl std::fmt::Display for ProtocolError {
	#[allow(clippy::too_many_lines)]
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidShare => write!(f, "invalid quorum key share"),
			Self::ReconstructionErrorEmptySecret => {
				write!(f, "failed to reconstruct quorum key: empty secret")
			}
			Self::ReconstructionErrorIncorrectPubKey => {
				write!(f, "reconstructed incorrect public key")
			}
			Self::IOError => write!(f, "filesystem error"),
			Self::InvalidManifestApproval(approval) => {
				write!(
					f,
					"invalid manifest approval from member '{}'",
					approval.member.alias
				)
			}
			Self::NotEnoughApprovals => write!(f, "not enough approvals"),
			Self::NoMatchingRoute(phase) => {
				write!(f, "no matching route for phase {phase:?}")
			}
			Self::InvalidPivotHash { expected, actual } => {
				write!(
					f,
					"invalid pivot hash: expected {expected}, got {actual}"
				)
			}
			Self::InvalidPivotEnv(e) => write!(f, "invalid pivot env: {e}"),
			Self::OversizeMsg => write!(f, "message too large"),
			Self::InvalidMsg => write!(f, "invalid message"),
			Self::EnclaveClient => write!(f, "enclave client error"),
			Self::DecryptionFailed => write!(f, "decryption failed"),
			Self::InvalidPrivateKey => write!(f, "invalid private key"),
			Self::FailedToParseFromString => {
				write!(f, "failed to parse from string")
			}
			Self::BadEphemeralKeyPath => write!(f, "bad ephemeral key path"),
			Self::CannotModifyPostPivotStatic => {
				write!(f, "cannot modify state after pivot")
			}
			Self::FailedToGetEphemeralKey(e) => {
				write!(f, "failed to get ephemeral key: {e:?}")
			}
			Self::FailedToPutEphemeralKey => {
				write!(f, "failed to put ephemeral key")
			}
			Self::CannotRotateNonExistentEphemeralKey => {
				write!(f, "cannot rotate non-existent ephemeral key")
			}
			Self::CannotDeleteEphemeralKey(e) => {
				write!(f, "cannot delete ephemeral key: {e}")
			}
			Self::FailedToGetQuorumKey(e) => {
				write!(f, "failed to get quorum key: {e:?}")
			}
			Self::FailedToPutQuorumKey => write!(f, "failed to put quorum key"),
			Self::FailedToGetManifestEnvelope => {
				write!(f, "failed to get manifest envelope")
			}
			Self::FailedToPutManifestEnvelope => {
				write!(f, "failed to put manifest envelope")
			}
			Self::FailedToPutPivot => write!(f, "failed to put pivot"),
			Self::AppClientRecvTimeout => {
				write!(f, "app client receive timeout")
			}
			Self::AppClientRecvInterrupted => {
				write!(f, "app client receive interrupted")
			}
			Self::AppClientRecvConnectionClosed => {
				write!(f, "app client connection closed")
			}
			Self::AppClientConnectError(e) => {
				write!(f, "app client connect error: {e}")
			}
			Self::AppClientSendError(e) => {
				write!(f, "app client send error: {e}")
			}
			Self::AppClientError(e) => write!(f, "app client error: {e}"),
			Self::OversizedPayload => write!(f, "oversized payload"),
			Self::ProtocolMsgDeserialization => {
				write!(f, "protocol message deserialization failed")
			}
			Self::BadShareSetApprovals => {
				write!(f, "unexpected share set approvals")
			}
			Self::CouldNotVerifyApproval => {
				write!(f, "could not verify approval")
			}
			Self::NotShareSetMember => write!(f, "not a share set member"),
			Self::NotManifestSetMember => {
				write!(f, "not a manifest set member")
			}
			Self::HybridError(e) => write!(f, "hybrid key error: {e:?}"),
			Self::InvalidDRKey(e) => {
				write!(f, "invalid hybrid DR key: {e:?}")
			}
			Self::IncorrectSecretLen => write!(f, "incorrect secret length"),
			Self::QosAttestError(e) => write!(f, "attestation error: {e}"),
			Self::DifferentQuorumKey { expected, actual } => {
				write!(
					f,
					"different quorum key: expected {expected}, got {actual}"
				)
			}
			Self::DifferentManifestSet { expected, actual } => {
				write!(
					f,
					"different manifest set: expected {expected}, got {actual}"
				)
			}
			Self::DifferentNamespaceName { expected, actual } => {
				write!(
					f,
					"different namespace name: expected '{expected}', got '{actual}'"
				)
			}
			Self::LowNonce { expected, actual } => {
				write!(
					f,
					"manifest nonce too low: expected >= {expected}, got {actual}"
				)
			}
			Self::DifferentPcr3 { expected, actual } => {
				write!(f, "different PCR3: expected {expected}, got {actual}")
			}
			Self::MissingEphemeralKey => write!(f, "missing ephemeral key"),
			Self::MissingLiveEphemeralKey => {
				write!(f, "missing precommitted live ephemeral key")
			}
			Self::InvalidEphemeralKey => write!(f, "invalid ephemeral key"),
			Self::InvalidEncryptedQuorumKeySignature => {
				write!(f, "invalid encrypted quorum key signature")
			}
			Self::EncryptedQuorumKeyInvalidLen => {
				write!(f, "encrypted quorum key has invalid length")
			}
			Self::InvalidQuorumSecret => write!(f, "invalid quorum secret"),
			Self::WrongQuorumKey => write!(f, "wrong quorum key"),
			Self::InvalidStateTransition(from, to) => {
				write!(f, "invalid state transition from {from:?} to {to:?}")
			}
			Self::DuplicateApproval => write!(f, "duplicate approval"),
			Self::DifferentManifest { expected, actual } => {
				write!(
					f,
					"different manifest: expected {expected}, got {actual}"
				)
			}
			Self::QosCrypto(e) => write!(f, "crypto error: {e}"),
			Self::PoolExpandError => write!(f, "pool expand error"),
			Self::DuplicateQuorumMember => {
				write!(
					f,
					"duplicate quorum member alias or public key component"
				)
			}
			Self::LegacyGenesisNotSupported => {
				write!(
					f,
					"genesis messages are only supported on the JSON wire encoding"
				)
			}
			Self::EphemeralKeyNotAttested => {
				write!(f, "ephemeral key does not match the attested binding")
			}
			Self::FailedToGetAppKey(e) => {
				write!(f, "failed to get the app key: {e:?}")
			}
			Self::FailedToPutAppKey => write!(f, "failed to put the app key"),
			Self::AppKeyTransferIncomplete => write!(
				f,
				"an app key transfer needs both the encrypted key and the sender's attestation"
			),
			Self::AppKeyTransferNotAttested(e) => {
				write!(f, "app key sender is not attested: {e}")
			}
			Self::InvalidAppKeySecret => {
				write!(f, "decrypted app key is not a master seed")
			}
			Self::AppKeyNotExpected => write!(
				f,
				"an app key was forwarded for a manifest with no app key minter"
			),
			Self::AppKeyMinterNotNamed => {
				write!(f, "the manifest names no app key minter")
			}
			Self::InvalidAppKeyMinter => {
				write!(f, "the manifest's app key minter is not a hybrid key")
			}
			Self::AppKeyMintOrderInvalid => write!(
				f,
				"the mint order is not the minter's signature for this boot"
			),
			Self::MissingPendingQuorumKey => {
				write!(f, "no quorum key is waiting for the app key")
			}
			Self::NoQuorumKeyManifestNamesQuorumKey => write!(
				f,
				"a manifest that boots without a quorum key names one"
			),
			Self::NoQuorumKeyManifestHasShareSet => write!(
				f,
				"a manifest that boots without a quorum key has a share set"
			),
			Self::NoQuorumKeyToForward => {
				write!(f, "the manifest has no quorum key to forward")
			}
			Self::InvalidShareTree(reason) => {
				write!(f, "invalid share tree: {reason}")
			}
			Self::ShareAlreadyProvisioned => {
				write!(f, "the member already provisioned a share")
			}
			Self::ShareNotForMember => {
				write!(f, "the posted shard is not an envelope key shard")
			}
			Self::QuorumKeyEnvelope(reason) => {
				write!(f, "quorum key envelope: {reason}")
			}
			Self::QuorumKeyEnvelopeNotProvided => write!(
				f,
				"post the quorum key envelope the manifest names before any shard"
			),
			Self::ReshareNotApproved(reason) => {
				write!(f, "reshare not approved: {reason}")
			}
		}
	}
}

impl std::error::Error for ProtocolError {}
