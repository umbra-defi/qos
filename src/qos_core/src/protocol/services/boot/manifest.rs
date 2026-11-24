//! Versioned manifest helpers.

use std::{borrow::Cow, io::Error};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::protocol::{Hash256, ProtocolError, QosHash};
#[cfg(test)]
use std::net::IpAddr;

use super::{
	Approval, BridgeConfig, KeyDigests, Manifest, ManifestEnvelope,
	ManifestEnvelopeV0, ManifestV0, Namespace, NitroConfig, RestartPolicy,
	ShareHolderNode,
};

mod builder;
pub mod v2;

pub use builder::{ManifestBuilder, ManifestBuilderError};
pub use v2::{
	DnsConfig, ManifestEnvelopeV2, ManifestSetV2, ManifestV2, ShareSetV2,
};

/// Schema version used by versioned manifest tooling.
#[derive(
	PartialEq,
	Eq,
	Debug,
	Clone,
	Copy,
	Default,
	serde::Serialize,
	serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ManifestVersion {
	/// Backwards-compatible manifest schema.
	V1,
	/// Explicitly versioned JSON manifest schema.
	#[default]
	V2,
}

/// Hash a serde value using canonical QOS JSON.
///
/// # Panics
///
/// Panics if `value` fails serialization, which would indicate a bug because
/// callers pass serde-serializable protocol types.
#[must_use]
pub fn canonical_json_hash<T: serde::Serialize>(value: &T) -> Hash256 {
	qos_json::hash(value).expect("Implements serde serialize")
}

/// Whether `buf` is a JSON object carrying a top-level `version` key.
fn declares_a_version(buf: &[u8]) -> bool {
	serde_json::from_slice::<serde_json::Value>(buf)
		.ok()
		.and_then(|value| value.get("version").cloned())
		.is_some()
}

/// Whether `buf` is a JSON envelope whose `manifest` declares a `version`.
fn enveloped_manifest_declares_a_version(buf: &[u8]) -> bool {
	serde_json::from_slice::<serde_json::Value>(buf)
		.ok()
		.and_then(|value| value.get("manifest")?.get("version").cloned())
		.is_some()
}

/// A manifest decoded with schema version preserved.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum VersionedManifest {
	/// Explicitly versioned JSON manifest schema.
	V2(ManifestV2),
	/// Backwards-compatible manifest schema.
	V1(Manifest),
	/// Legacy original manifest schema.
	V0(ManifestV0),
}

impl From<ManifestV2> for VersionedManifest {
	fn from(value: ManifestV2) -> Self {
		Self::V2(value)
	}
}

impl From<Manifest> for VersionedManifest {
	fn from(value: Manifest) -> Self {
		Self::V1(value)
	}
}

impl From<ManifestV0> for VersionedManifest {
	fn from(value: ManifestV0) -> Self {
		Self::V0(value)
	}
}

// NOTE: This is intentionally "illegal" for the v2 variant: v2 is JSON-only,
// but we still implement Borsh traits on the enum for v1/v0 backcompat.
impl BorshSerialize for VersionedManifest {
	fn serialize<W: borsh::io::Write>(
		&self,
		writer: &mut W,
	) -> borsh::io::Result<()> {
		match self {
			Self::V2(_) => Err(borsh::io::Error::other(
				"manifest v2 is json-only and cannot be borsh serialized",
			)),
			Self::V1(manifest) => manifest.serialize(writer),
			Self::V0(manifest) => manifest.serialize(writer),
		}
	}
}

impl BorshDeserialize for VersionedManifest {
	fn deserialize_reader<R: borsh::io::Read>(
		reader: &mut R,
	) -> borsh::io::Result<Self> {
		let mut buf = vec![];
		reader.read_to_end(&mut buf)?;
		super::decode_borsh(&buf, Self::V1, Self::V0)
	}
}

impl VersionedManifest {
	/// Return the manifest hash using the encoding for the embedded schema.
	#[must_use]
	pub fn manifest_hash(&self) -> Hash256 {
		match self {
			Self::V2(manifest) => canonical_json_hash(manifest),
			Self::V1(manifest) => manifest.qos_hash(),
			Self::V0(manifest) => manifest.qos_hash(),
		}
	}

	/// Return the manifest namespace.
	#[must_use]
	pub fn namespace(&self) -> &Namespace {
		match self {
			Self::V2(manifest) => &manifest.namespace,
			Self::V1(manifest) => &manifest.namespace,
			Self::V0(manifest) => &manifest.namespace,
		}
	}

	/// Return the manifest set authorized to approve manifest changes, its
	/// members named by key digest; a v0 or v1 manifest's full keys are
	/// digested.
	///
	/// # Errors
	///
	/// A [`ProtocolError::HybridError`] when a v0 or v1 member's key is not a
	/// hybrid key.
	pub fn manifest_set(
		&self,
	) -> Result<Cow<'_, ManifestSetV2>, ProtocolError> {
		match self {
			Self::V2(manifest) => Ok(Cow::Borrowed(&manifest.manifest_set)),
			Self::V1(manifest) => {
				Ok(Cow::Owned((&manifest.manifest_set).try_into()?))
			}
			Self::V0(manifest) => {
				Ok(Cow::Owned((&manifest.manifest_set).try_into()?))
			}
		}
	}

	/// Return the holder tree the quorum key envelope's key is dealt over, or `None` for a v0 or
	/// v1 manifest, whose flat share set predates the envelope and cannot be provisioned.
	#[must_use]
	pub fn share_set(&self) -> Option<&ShareSetV2> {
		match self {
			Self::V2(manifest) => Some(&manifest.share_set),
			Self::V1(_) | Self::V0(_) => None,
		}
	}

	/// Return the enclave configuration.
	#[must_use]
	pub fn enclave(&self) -> &NitroConfig {
		match self {
			Self::V2(manifest) => &manifest.enclave,
			Self::V1(manifest) => &manifest.enclave,
			Self::V0(manifest) => &manifest.enclave,
		}
	}

	/// Return the hybrid public key allowed to order this manifest's app key
	/// minted, or `None` when the manifest has no app key. Only v2 manifests
	/// can name one.
	#[must_use]
	pub fn app_key_minter(&self) -> Option<&KeyDigests> {
		match self {
			Self::V2(manifest) => manifest.app_key_minter.as_ref(),
			Self::V1(_) | Self::V0(_) => None,
		}
	}

	/// Return whether the manifest boots without a quorum key. Only v2
	/// manifests can.
	#[must_use]
	pub fn no_quorum_key(&self) -> bool {
		match self {
			Self::V2(manifest) => manifest.no_quorum_key,
			Self::V1(_) | Self::V0(_) => false,
		}
	}

	/// Return the expected pivot binary hash.
	#[must_use]
	pub fn pivot_hash(&self) -> &Hash256 {
		match self {
			Self::V2(manifest) => &manifest.pivot.hash,
			Self::V1(manifest) => &manifest.pivot.hash,
			Self::V0(manifest) => &manifest.pivot.hash,
		}
	}

	/// Return the pivot restart policy.
	#[must_use]
	pub fn restart(&self) -> RestartPolicy {
		match self {
			Self::V2(manifest) => manifest.pivot.restart,
			Self::V1(manifest) => manifest.pivot.restart,
			Self::V0(manifest) => manifest.pivot.restart,
		}
	}

	/// Return the pivot command-line arguments.
	#[must_use]
	pub fn args(&self) -> &[String] {
		match self {
			Self::V2(manifest) => &manifest.pivot.args,
			Self::V1(manifest) => &manifest.pivot.args,
			Self::V0(manifest) => &manifest.pivot.args,
		}
	}

	/// Return bridge configuration entries, or an empty slice for v0 manifests.
	#[must_use]
	pub fn bridge_config(&self) -> &[BridgeConfig] {
		match self {
			Self::V2(manifest) => &manifest.pivot.bridge_config,
			Self::V1(manifest) => &manifest.pivot.bridge_config,
			Self::V0(_) => &[],
		}
	}

	/// Return whether pivot debug mode is enabled.
	#[must_use]
	pub fn debug_mode(&self) -> bool {
		match self {
			Self::V2(manifest) => manifest.pivot.debug_mode,
			Self::V1(manifest) => manifest.pivot.debug_mode,
			Self::V0(_) => false,
		}
	}

	/// Return DNS resolver configuration for v2 manifests.
	#[must_use]
	pub fn dns_config(&self) -> Option<&DnsConfig> {
		match self {
			Self::V2(manifest) => manifest.dns.as_ref(),
			Self::V1(_) | Self::V0(_) => None,
		}
	}

	/// Return the human readable schema version label for this manifest.
	#[must_use]
	pub const fn version_label(&self) -> &'static str {
		match self {
			Self::V2(_) => "v2",
			Self::V1(_) => "v1",
			Self::V0(_) => "v0",
		}
	}

	/// Read a manifest while preserving the recognized schema version.
	///
	/// The older schemas are recognized by shape, so a manifest that declares
	/// a `version` must decode as [`ManifestV2`] rather than fall back to one
	/// of them.
	///
	/// # Errors
	///
	/// Returns an [`std::io::Error`] when the bytes cannot be decoded as any
	/// supported manifest schema or encoding, or when a manifest declares a
	/// `version` that does not match the schema it is written in.
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, Error> {
		if declares_a_version(buf) {
			return serde_json::from_slice::<ManifestV2>(buf)
				.map(Self::V2)
				.map_err(|e| Error::other(e.to_string()));
		}
		if let Ok(manifest) = serde_json::from_slice::<Manifest>(buf) {
			return Ok(Self::V1(manifest));
		}
		if let Ok(manifest) = serde_json::from_slice::<ManifestV0>(buf) {
			return Ok(Self::V0(manifest));
		}
		super::decode_borsh(buf, Self::V1, Self::V0)
	}

	/// Serialize this manifest using its storage encoding.
	///
	/// # Errors
	///
	/// Returns an [`std::io::Error`] when serialization fails.
	pub fn to_storage_vec(&self) -> Result<Vec<u8>, Error> {
		match self {
			Self::V2(manifest) => qos_json::to_vec(manifest)
				.map_err(|e| Error::other(e.to_string())),
			Self::V1(manifest) => serde_json::to_vec(manifest)
				.map_err(|e| Error::other(e.to_string())),
			Self::V0(manifest) => serde_json::to_vec(manifest)
				.map_err(|e| Error::other(e.to_string())),
		}
	}
}

/// A manifest envelope decoded with schema version preserved.
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum VersionedManifestEnvelope {
	/// Explicitly versioned JSON manifest envelope schema.
	V2(ManifestEnvelopeV2),
	/// Backwards-compatible manifest envelope schema.
	V1(ManifestEnvelope),
	/// Legacy original manifest envelope schema.
	V0(ManifestEnvelopeV0),
}

impl From<ManifestEnvelopeV2> for VersionedManifestEnvelope {
	fn from(value: ManifestEnvelopeV2) -> Self {
		Self::V2(value)
	}
}

impl From<ManifestEnvelope> for VersionedManifestEnvelope {
	fn from(value: ManifestEnvelope) -> Self {
		Self::V1(value)
	}
}

impl From<&ManifestEnvelope> for VersionedManifestEnvelope {
	fn from(value: &ManifestEnvelope) -> Self {
		Self::V1(value.clone())
	}
}

impl From<ManifestEnvelopeV0> for VersionedManifestEnvelope {
	fn from(value: ManifestEnvelopeV0) -> Self {
		Self::V0(value)
	}
}

impl From<&VersionedManifestEnvelope> for VersionedManifestEnvelope {
	fn from(value: &VersionedManifestEnvelope) -> Self {
		value.clone()
	}
}

impl From<&Box<VersionedManifestEnvelope>> for VersionedManifestEnvelope {
	fn from(value: &Box<VersionedManifestEnvelope>) -> Self {
		(**value).clone()
	}
}

// NOTE: Same backcompat carve-out as VersionedManifest above: the enum keeps
// a Borsh impl for v1/v0, while v2 explicitly errors.
impl BorshSerialize for VersionedManifestEnvelope {
	fn serialize<W: borsh::io::Write>(
		&self,
		writer: &mut W,
	) -> borsh::io::Result<()> {
		match self {
			Self::V2(_) => Err(borsh::io::Error::other(
				"manifest envelope v2 is json-only and cannot be borsh serialized",
			)),
			Self::V1(envelope) => envelope.serialize(writer),
			Self::V0(envelope) => envelope.serialize(writer),
		}
	}
}

impl BorshDeserialize for VersionedManifestEnvelope {
	fn deserialize_reader<R: borsh::io::Read>(
		reader: &mut R,
	) -> borsh::io::Result<Self> {
		let mut buf = vec![];
		reader.read_to_end(&mut buf)?;
		super::decode_borsh(&buf, Self::V1, Self::V0)
	}
}

impl VersionedManifestEnvelope {
	/// Consume the envelope and return its embedded manifest.
	#[must_use]
	pub fn manifest(self) -> VersionedManifest {
		match self {
			Self::V2(envelope) => VersionedManifest::V2(envelope.manifest),
			Self::V1(envelope) => VersionedManifest::V1(envelope.manifest),
			Self::V0(envelope) => VersionedManifest::V0(envelope.manifest),
		}
	}

	/// Return approvals from manifest set members.
	#[must_use]
	pub fn manifest_set_approvals(&self) -> &[Approval] {
		match self {
			Self::V2(envelope) => &envelope.manifest_set_approvals,
			Self::V1(envelope) => &envelope.manifest_set_approvals,
			Self::V0(envelope) => &envelope.manifest_set_approvals,
		}
	}

	/// Return approvals from share set members.
	#[must_use]
	pub fn share_set_approvals(&self) -> &[Approval] {
		match self {
			Self::V2(envelope) => &envelope.share_set_approvals,
			Self::V1(envelope) => &envelope.share_set_approvals,
			Self::V0(envelope) => &envelope.share_set_approvals,
		}
	}

	/// Return the embedded manifest hash using its schema-specific encoding.
	#[must_use]
	pub fn manifest_hash(&self) -> Hash256 {
		match self {
			Self::V2(envelope) => canonical_json_hash(&envelope.manifest),
			Self::V1(envelope) => envelope.manifest.qos_hash(),
			Self::V0(envelope) => envelope.manifest.qos_hash(),
		}
	}

	/// Return the embedded manifest set, its members named by key digest.
	///
	/// # Errors
	///
	/// As [`VersionedManifest::manifest_set`].
	pub fn manifest_set(
		&self,
	) -> Result<Cow<'_, ManifestSetV2>, ProtocolError> {
		match self {
			Self::V2(envelope) => {
				Ok(Cow::Borrowed(&envelope.manifest.manifest_set))
			}
			Self::V1(envelope) => {
				Ok(Cow::Owned((&envelope.manifest.manifest_set).try_into()?))
			}
			Self::V0(envelope) => {
				Ok(Cow::Owned((&envelope.manifest.manifest_set).try_into()?))
			}
		}
	}

	/// Return the embedded namespace.
	#[must_use]
	pub fn namespace(&self) -> &Namespace {
		match self {
			Self::V2(envelope) => &envelope.manifest.namespace,
			Self::V1(envelope) => &envelope.manifest.namespace,
			Self::V0(envelope) => &envelope.manifest.namespace,
		}
	}

	/// Return the embedded manifest's holder tree, or `None` for a v0 or v1 manifest.
	#[must_use]
	pub fn share_set(&self) -> Option<&ShareSetV2> {
		match self {
			Self::V2(envelope) => Some(&envelope.manifest.share_set),
			Self::V1(_) | Self::V0(_) => None,
		}
	}

	/// Return the expected pivot binary hash from the embedded manifest.
	#[must_use]
	pub fn pivot_hash(&self) -> &Hash256 {
		match self {
			Self::V2(envelope) => &envelope.manifest.pivot.hash,
			Self::V1(envelope) => &envelope.manifest.pivot.hash,
			Self::V0(envelope) => &envelope.manifest.pivot.hash,
		}
	}

	/// Return the enclave configuration from the embedded manifest.
	#[must_use]
	pub fn enclave(&self) -> &NitroConfig {
		match self {
			Self::V2(e) => &e.manifest.enclave,
			Self::V1(e) => &e.manifest.enclave,
			Self::V0(e) => &e.manifest.enclave,
		}
	}

	/// Return the embedded manifest's app key minter, or `None` when it has
	/// no app key. Only v2 manifests can name one.
	#[must_use]
	pub fn app_key_minter(&self) -> Option<&KeyDigests> {
		match self {
			Self::V2(e) => e.manifest.app_key_minter.as_ref(),
			Self::V1(_) | Self::V0(_) => None,
		}
	}

	/// Return whether the embedded manifest boots without a quorum key. Only
	/// v2 manifests can.
	#[must_use]
	pub fn no_quorum_key(&self) -> bool {
		match self {
			Self::V2(e) => e.manifest.no_quorum_key,
			Self::V1(_) | Self::V0(_) => false,
		}
	}

	/// Verify manifest-set approvals against the embedded manifest hash and
	/// threshold policy.
	///
	/// # Errors
	///
	/// Returns a [`ProtocolError`] when signatures are invalid, members are
	/// unauthorized, duplicate approvals exist, or the threshold is not met.
	pub fn check_approvals(&self) -> Result<(), ProtocolError> {
		let manifest_set = self.manifest_set()?;
		manifest_set.validate()?;

		let manifest_hash = self.manifest_hash();
		let mut uniq_members = std::collections::HashSet::new();

		for approval in self.manifest_set_approvals() {
			let member_pub_key =
				qos_hybrid::HybridPublic::from_bytes(&approval.member.pub_key)?;
			let is_valid_signature = member_pub_key
				.verify(&manifest_hash, &approval.signature)
				.is_ok();
			if !is_valid_signature {
				return Err(ProtocolError::InvalidManifestApproval(
					approval.clone(),
				));
			}
			// The member is named by its key's digests, unique across the tree,
			// so its place counts it once.
			let Some(path) = manifest_set.locate(&approval.member)? else {
				return Err(ProtocolError::NotManifestSetMember);
			};
			if !uniq_members.insert(path) {
				return Err(ProtocolError::DuplicateApproval);
			}
		}
		let approvers: Vec<_> = self
			.manifest_set_approvals()
			.iter()
			.map(|approval| approval.member.clone())
			.collect();
		super::ensure_unique_members(&approvers)?;

		if !manifest_set.is_satisfied_by_members(&approvers)? {
			return Err(ProtocolError::NotEnoughApprovals);
		}

		Ok(())
	}

	/// Read a manifest envelope while preserving the recognized schema version.
	///
	/// As with [`VersionedManifest::try_from_slice_compat`], an envelope whose
	/// manifest declares a `version` must decode as [`ManifestEnvelopeV2`].
	///
	/// # Errors
	///
	/// Returns an [`std::io::Error`] when the bytes cannot be decoded as any
	/// supported manifest envelope schema or encoding, or when the enveloped
	/// manifest declares a `version` that does not match its schema.
	pub fn try_from_slice_compat(buf: &[u8]) -> Result<Self, Error> {
		if enveloped_manifest_declares_a_version(buf) {
			return serde_json::from_slice::<ManifestEnvelopeV2>(buf)
				.map(Self::V2)
				.map_err(|e| Error::other(e.to_string()));
		}
		if let Ok(envelope) = serde_json::from_slice::<ManifestEnvelope>(buf) {
			return Ok(Self::V1(envelope));
		}
		if let Ok(envelope) = serde_json::from_slice::<ManifestEnvelopeV0>(buf)
		{
			return Ok(Self::V0(envelope));
		}
		super::decode_borsh(buf, Self::V1, Self::V0)
	}

	/// Serialize this manifest envelope using its storage encoding.
	///
	/// # Errors
	///
	/// Returns an [`std::io::Error`] when serialization fails.
	pub fn to_storage_vec(&self) -> Result<Vec<u8>, Error> {
		match self {
			Self::V2(envelope) => qos_json::to_vec(envelope)
				.map_err(|e| Error::other(e.to_string())),
			Self::V1(envelope) => serde_json::to_vec(envelope)
				.map_err(|e| Error::other(e.to_string())),
			Self::V0(envelope) => serde_json::to_vec(envelope)
				.map_err(|e| Error::other(e.to_string())),
		}
	}
}

#[cfg(test)]
mod tests {
	use qos_hybrid::HybridPair;

	use super::*;
	use crate::protocol::{
		QosHash,
		services::boot::{
			ManifestSet, MemberPubKey, PatchSet, PivotConfig, PivotConfigV0,
			PivotEnv, QuorumMember, ShareSet,
		},
	};

	fn sample_member(pair: &HybridPair) -> QuorumMember {
		QuorumMember {
			alias: "member-1".to_string(),
			pub_key: pair.public_key().to_bytes(),
		}
	}

	fn sample_v2_manifest(member: QuorumMember) -> ManifestV2 {
		ManifestV2 {
			version: ManifestVersion::V2,
			namespace: Namespace {
				name: "test-namespace".to_string(),
				nonce: 42,
				quorum_key: vec![7; 33],
			},
			pivot: v2::PivotConfigV2 {
				hash: [9; 32],
				restart: RestartPolicy::Never,
				bridge_config: vec![],
				debug_mode: false,
				args: vec!["--foo".to_string()],
				env: PivotEnv::new(),
			},
			manifest_set: (&ManifestSet {
				threshold: 1,
				members: vec![member.clone()],
			})
				.try_into()
				.unwrap(),
			share_set: ShareSet { threshold: 1, members: vec![member] }
				.try_into()
				.unwrap(),
			enclave: NitroConfig {
				pcr0: vec![0; 48],
				pcr1: vec![1; 48],
				pcr2: vec![2; 48],
				pcr3: vec![3; 48],
				aws_root_certificate: vec![],
				qos_commit: "commit".to_string(),
			},
			dns: None,
			app_key_minter: None,
			no_quorum_key: false,
		}
	}

	fn sample_v1_manifest(member: QuorumMember) -> Manifest {
		Manifest {
			namespace: Namespace {
				name: "test-namespace".to_string(),
				nonce: 42,
				quorum_key: vec![7; 33],
			},
			pivot: PivotConfig {
				hash: [9; 32],
				restart: RestartPolicy::Never,
				bridge_config: vec![],
				debug_mode: false,
				args: vec!["--foo".to_string()],
			},
			manifest_set: ManifestSet {
				threshold: 1,
				members: vec![member.clone()],
			},
			share_set: ShareSet { threshold: 1, members: vec![member.clone()] },
			enclave: NitroConfig {
				pcr0: vec![0; 48],
				pcr1: vec![1; 48],
				pcr2: vec![2; 48],
				pcr3: vec![3; 48],
				aws_root_certificate: vec![],
				qos_commit: "commit".to_string(),
			},
			patch_set: PatchSet {
				threshold: 1,
				members: vec![MemberPubKey { pub_key: member.pub_key }],
			},
		}
	}

	fn sample_v0_manifest(member: QuorumMember) -> ManifestV0 {
		ManifestV0 {
			namespace: Namespace {
				name: "test-namespace".to_string(),
				nonce: 42,
				quorum_key: vec![7; 33],
			},
			pivot: PivotConfigV0 {
				hash: [9; 32],
				restart: RestartPolicy::Never,
				args: vec!["--foo".to_string()],
			},
			manifest_set: ManifestSet {
				threshold: 1,
				members: vec![member.clone()],
			},
			share_set: ShareSet { threshold: 1, members: vec![member.clone()] },
			enclave: NitroConfig {
				pcr0: vec![0; 48],
				pcr1: vec![1; 48],
				pcr2: vec![2; 48],
				pcr3: vec![3; 48],
				aws_root_certificate: vec![],
				qos_commit: "commit".to_string(),
			},
			patch_set: PatchSet {
				threshold: 1,
				members: vec![MemberPubKey { pub_key: member.pub_key }],
			},
		}
	}

	#[test]
	fn v2_manifest_omits_dns_when_absent() {
		let pair = HybridPair::generate().unwrap();
		let manifest = sample_v2_manifest(sample_member(&pair));
		let value = serde_json::to_value(&manifest).unwrap();

		assert!(value.get("dns").is_none());
	}

	#[test]
	fn v2_manifest_round_trips_dns_resolvers() {
		let pair = HybridPair::generate().unwrap();
		let mut manifest = sample_v2_manifest(sample_member(&pair));
		manifest.dns = Some(DnsConfig {
			resolvers: vec![
				"1.1.1.1".parse().unwrap(),
				"2606:4700:4700::1111".parse().unwrap(),
			],
		});

		let value = serde_json::to_value(&manifest).unwrap();
		assert_eq!(value["dns"]["resolvers"][0], "1.1.1.1");
		assert_eq!(value["dns"]["resolvers"][1], "2606:4700:4700::1111");

		let decoded: ManifestV2 = serde_json::from_value(value).unwrap();
		assert_eq!(decoded.dns, manifest.dns);
	}

	#[test]
	fn v2_manifest_rejects_invalid_dns_resolver() {
		let pair = HybridPair::generate().unwrap();
		let mut value =
			serde_json::to_value(sample_v2_manifest(sample_member(&pair)))
				.unwrap();
		value["dns"] = serde_json::json!({
			"resolvers": ["not-an-ip"]
		});

		assert!(serde_json::from_value::<ManifestV2>(value).is_err());
	}

	#[test]
	fn v2_manifest_rejects_a_version_other_than_v2() {
		let pair = HybridPair::generate().unwrap();
		let manifest = sample_v2_manifest(sample_member(&pair));
		let mut value = serde_json::to_value(&manifest).unwrap();

		for version in [
			serde_json::json!("v1"),
			serde_json::json!("v3"),
			serde_json::json!(2),
		] {
			value["version"] = version.clone();
			assert!(
				serde_json::from_value::<ManifestV2>(value.clone()).is_err(),
				"version {version} should not decode as a v2 manifest"
			);
		}

		value["version"] = serde_json::json!("v2");
		assert_eq!(
			serde_json::from_value::<ManifestV2>(value).unwrap(),
			manifest
		);
	}

	#[test]
	fn declared_version_never_falls_back_to_an_older_schema() {
		let pair = HybridPair::generate().unwrap();
		let member = sample_member(&pair);

		let mut v1 =
			serde_json::to_value(sample_v1_manifest(member.clone())).unwrap();
		v1["version"] = serde_json::json!("v2");
		let error = VersionedManifest::try_from_slice_compat(
			&serde_json::to_vec(&v1).unwrap(),
		)
		.unwrap_err();
		assert!(
			error.to_string().contains("patchSet")
				|| error.to_string().contains("pubKey"),
			"a v1 manifest declared v2 must fail as v2, on a v1-only field: {error}"
		);

		let mut v0 =
			serde_json::to_value(sample_v0_manifest(member.clone())).unwrap();
		v0["version"] = serde_json::json!("v1");
		assert!(
			VersionedManifest::try_from_slice_compat(
				&serde_json::to_vec(&v0).unwrap()
			)
			.is_err()
		);

		// Undeclared manifests still resolve by shape.
		let v1 =
			serde_json::to_vec(&sample_v1_manifest(member.clone())).unwrap();
		assert!(matches!(
			VersionedManifest::try_from_slice_compat(&v1).unwrap(),
			VersionedManifest::V1(_)
		));
		let v0 = serde_json::to_vec(&sample_v0_manifest(member)).unwrap();
		assert!(matches!(
			VersionedManifest::try_from_slice_compat(&v0).unwrap(),
			VersionedManifest::V0(_)
		));
	}

	#[test]
	fn enveloped_declared_version_never_falls_back_to_an_older_schema() {
		let pair = HybridPair::generate().unwrap();
		let member = sample_member(&pair);

		let envelope = ManifestEnvelope {
			manifest: sample_v1_manifest(member.clone()),
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		};
		let mut value = serde_json::to_value(&envelope).unwrap();
		value["manifest"]["version"] = serde_json::json!("v2");
		assert!(
			VersionedManifestEnvelope::try_from_slice_compat(
				&serde_json::to_vec(&value).unwrap()
			)
			.is_err()
		);

		let undeclared = serde_json::to_vec(&envelope).unwrap();
		assert!(matches!(
			VersionedManifestEnvelope::try_from_slice_compat(&undeclared)
				.unwrap(),
			VersionedManifestEnvelope::V1(_)
		));
	}

	#[test]
	fn versioned_manifest_dns_config_is_v2_only() {
		let pair = HybridPair::generate().unwrap();
		let member = sample_member(&pair);
		let mut v2 = sample_v2_manifest(member.clone());
		v2.dns =
			Some(DnsConfig { resolvers: vec!["1.1.1.1".parse().unwrap()] });

		assert_eq!(
			VersionedManifest::V2(v2).dns_config().unwrap().resolvers,
			vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
		);
		assert!(
			VersionedManifest::V1(sample_v1_manifest(member.clone()))
				.dns_config()
				.is_none()
		);
		assert!(
			VersionedManifest::V0(sample_v0_manifest(member))
				.dns_config()
				.is_none()
		);
	}

	#[test]
	fn v2_manifest_decode_and_hash_uses_canonical_json() {
		let pair = HybridPair::generate().unwrap();
		let manifest = sample_v2_manifest(sample_member(&pair));
		let bytes = qos_json::to_vec(&manifest).unwrap();

		let decoded = VersionedManifest::try_from_slice_compat(&bytes).unwrap();
		assert!(matches!(decoded, VersionedManifest::V2(_)));
		assert_eq!(decoded.manifest_hash(), canonical_json_hash(&manifest));
	}

	#[test]
	fn v2_manifest_names_no_quorum_key_mode_only_when_set() {
		let pair = HybridPair::generate().unwrap();
		let mut manifest = sample_v2_manifest(sample_member(&pair));
		let with_quorum_key =
			String::from_utf8(qos_json::to_vec(&manifest).unwrap()).unwrap();
		assert!(
			!with_quorum_key.contains("noQuorumKey"),
			"an existing manifest's JSON, and so its hash, must not change"
		);

		manifest.no_quorum_key = true;
		let bytes = qos_json::to_vec(&manifest).unwrap();
		assert!(
			String::from_utf8(bytes.clone())
				.unwrap()
				.contains("\"noQuorumKey\":true")
		);
		let decoded = VersionedManifest::try_from_slice_compat(&bytes).unwrap();
		assert!(decoded.no_quorum_key());
	}

	#[test]
	fn v2_envelope_decode_and_approval_verification_uses_json_hash() {
		let pair = HybridPair::generate().unwrap();
		let member = sample_member(&pair);
		let manifest = sample_v2_manifest(member.clone());
		let manifest_hash = canonical_json_hash(&manifest);
		let envelope = ManifestEnvelopeV2 {
			manifest,
			manifest_set_approvals: vec![Approval {
				signature: pair.sign(&manifest_hash).unwrap(),
				member,
			}],
			share_set_approvals: vec![],
		};
		let bytes = qos_json::to_vec(&envelope).unwrap();

		let decoded =
			VersionedManifestEnvelope::try_from_slice_compat(&bytes).unwrap();
		assert!(matches!(decoded, VersionedManifestEnvelope::V2(_)));
		assert_eq!(decoded.manifest_hash(), manifest_hash);
		assert!(decoded.check_approvals().is_ok());
	}

	#[test]
	fn versioned_check_approvals_rejects_same_key_under_different_aliases() {
		let pair = HybridPair::generate().unwrap();
		let alias_a = QuorumMember {
			alias: "alias-a".to_string(),
			pub_key: pair.public_key().to_bytes(),
		};
		let alias_b = QuorumMember {
			alias: "alias-b".to_string(),
			pub_key: pair.public_key().to_bytes(),
		};

		let mut manifest = sample_v2_manifest(alias_a.clone());
		manifest.manifest_set = (&ManifestSet {
			threshold: 2,
			members: vec![alias_a.clone(), alias_b.clone()],
		})
			.try_into()
			.unwrap();

		let manifest_hash = canonical_json_hash(&manifest);
		let signature = pair.sign(&manifest_hash).unwrap();
		let envelope = VersionedManifestEnvelope::V2(ManifestEnvelopeV2 {
			manifest,
			manifest_set_approvals: vec![
				Approval { signature: signature.clone(), member: alias_a },
				Approval { signature, member: alias_b },
			],
			share_set_approvals: vec![],
		});

		let err = envelope.check_approvals().unwrap_err();
		assert_eq!(err, ProtocolError::DuplicateQuorumMember);
	}

	#[test]
	fn a_tree_manifest_set_boots_only_on_approvals_that_satisfy_it() {
		use crate::protocol::services::{
			boot::ShareGroup, genesis::GenesisSet,
		};
		let pairs: Vec<HybridPair> =
			(0..3).map(|_| HybridPair::generate().unwrap()).collect();
		let members: Vec<QuorumMember> = ["u0", "u1", "e0"]
			.iter()
			.zip(&pairs)
			.map(|(alias, pair)| QuorumMember {
				alias: (*alias).to_string(),
				pub_key: pair.public_key().to_bytes(),
			})
			.collect();
		let group =
			|alias: &str, threshold, members: &[QuorumMember]| ShareGroup {
				alias: alias.to_string(),
				threshold,
				members: members.to_vec(),
				groups: vec![],
			};
		let mut manifest = sample_v2_manifest(members[0].clone());
		manifest.manifest_set = ManifestSetV2::from_tree(&GenesisSet {
			threshold: 2,
			members: vec![],
			groups: vec![
				group("umbra", 1, &members[0..2]),
				group("external", 1, &members[2..3]),
			],
		})
		.unwrap();
		let manifest_hash = canonical_json_hash(&manifest);
		let envelope = |signers: &[usize]| {
			VersionedManifestEnvelope::V2(ManifestEnvelopeV2 {
				manifest: manifest.clone(),
				manifest_set_approvals: signers
					.iter()
					.map(|i| Approval {
						signature: pairs[*i].sign(&manifest_hash).unwrap(),
						member: members[*i].clone(),
					})
					.collect(),
				share_set_approvals: vec![],
			})
		};
		assert!(envelope(&[0, 2]).check_approvals().is_ok());
		assert!(envelope(&[1, 2]).check_approvals().is_ok());
		assert_eq!(
			envelope(&[0, 1]).check_approvals(),
			Err(ProtocolError::NotEnoughApprovals),
			"both Umbra members satisfy only their own group"
		);
		assert_eq!(
			envelope(&[0, 2, 0]).check_approvals(),
			Err(ProtocolError::DuplicateApproval)
		);
	}

	#[test]
	fn hash_dispatch_uses_borsh_for_v1_v0() {
		let pair = HybridPair::generate().unwrap();
		let member = sample_member(&pair);
		let v1 = sample_v1_manifest(member.clone());
		let v0 = sample_v0_manifest(member);

		assert_eq!(
			VersionedManifest::V1(v1.clone()).manifest_hash(),
			v1.qos_hash()
		);
		assert_eq!(
			VersionedManifest::V0(v0.clone()).manifest_hash(),
			v0.qos_hash()
		);
	}

	#[test]
	fn borsh_serialization_rejects_v2_variants() {
		let pair = HybridPair::generate().unwrap();
		let member = sample_member(&pair);
		let v2_manifest = sample_v2_manifest(member.clone());
		let v2_envelope = ManifestEnvelopeV2 {
			manifest: v2_manifest.clone(),
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		};

		assert!(borsh::to_vec(&VersionedManifest::V2(v2_manifest)).is_err());
		assert!(
			borsh::to_vec(&VersionedManifestEnvelope::V2(v2_envelope)).is_err()
		);
	}

	#[test]
	fn ambiguous_borsh_manifest_is_rejected() {
		let mut manifest = ManifestV0::default();
		manifest.pivot.args = vec!["\u{1}".to_string(), "\0\0\0\0".to_string()];
		let envelope = ManifestEnvelopeV0 {
			manifest: manifest.clone(),
			manifest_set_approvals: vec![],
			share_set_approvals: vec![],
		};
		let envelope_bytes = borsh::to_vec(&envelope).unwrap();
		let bytes = borsh::to_vec(&manifest).unwrap();

		assert!(ManifestEnvelope::try_from_slice(&envelope_bytes).is_ok());
		assert!(ManifestEnvelopeV0::try_from_slice(&envelope_bytes).is_ok());
		assert!(
			VersionedManifestEnvelope::try_from_slice_compat(&envelope_bytes)
				.is_err()
		);
		assert!(Manifest::try_from_slice(&bytes).is_ok());
		assert!(ManifestV0::try_from_slice(&bytes).is_ok());
		assert!(VersionedManifest::try_from_slice_compat(&bytes).is_err());
	}
}
