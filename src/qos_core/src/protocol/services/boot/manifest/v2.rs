//! Explicitly versioned JSON manifest schema (v2).

use std::net::IpAddr;

use crate::protocol::{
	Hash256,
	services::boot::{
		Approval, BridgeConfig, KeyDigests, MemberDigest, Namespace,
		NitroConfig, PivotEnv, RestartPolicy, ShareHolderGroup,
	},
};

/// The manifest set of a v2 manifest: `threshold` of its members must approve a manifest. Members
/// are named by key digest; each approval carries the approver's full key, which must digest to a
/// member.
#[derive(
	PartialEq, Eq, Debug, Clone, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestSetV2 {
	/// Approvals needed.
	#[serde(with = "qos_json::string_or_numeric")]
	pub threshold: u32,
	/// Members who may approve.
	pub members: Vec<MemberDigest>,
}

use super::ManifestVersion;

/// DNS resolver configuration (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsConfig {
	/// Resolver IP addresses to write as `nameserver` entries.
	pub resolvers: Vec<IpAddr>,
}

/// JSON-only pivot binary configuration (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(any(feature = "mock", test), derive(Default))]
pub struct PivotConfigV2 {
	/// Hash of the pivot binary, taken from the binary as a `Vec<u8>`.
	#[serde(with = "qos_hex::serde")]
	pub hash: Hash256,
	/// Restart policy for running the pivot binary.
	pub restart: RestartPolicy,
	/// Bridge host configuration for the pivot is a set of per-port rules.
	pub bridge_config: Vec<BridgeConfig>,
	/// Whether we're invoking the enclave and pivot in DEBUG mode.
	pub debug_mode: bool,
	/// Arguments to invoke the binary with.
	pub args: Vec<String>,
	/// Environment variables to inject into the pivot process.
	#[serde(default, skip_serializing_if = "PivotEnv::is_empty")]
	pub env: PivotEnv,
}

/// The share set of a v2 manifest: the top of the holder tree the quorum key envelope's key is
/// dealt over, satisfied once `threshold` of its children are, its members first, then its groups.
/// Holders are named by key digest, and `envelope_digest` names the envelope. A manifest without a
/// quorum key has an empty one, which serializes as `{"threshold":0,"members":[]}`.
#[derive(
	PartialEq, Eq, Debug, Clone, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShareSetV2 {
	/// Children that must be satisfied to rebuild the envelope key.
	#[serde(with = "qos_json::string_or_numeric")]
	pub threshold: u32,
	/// Holders of a shard of the envelope key.
	pub members: Vec<MemberDigest>,
	/// Groups, each rebuilding one share of the envelope key.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub groups: Vec<ShareHolderGroup>,
	/// [`QuorumKeyEnvelope::digest`] of the envelope the quorum key is sealed in; absent only for
	/// a manifest without a quorum key.
	///
	/// [`QuorumKeyEnvelope::digest`]: crate::protocol::services::envelope::QuorumKeyEnvelope::digest
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		with = "qos_hex::serde::option"
	)]
	pub envelope_digest: Option<Vec<u8>>,
}

/// Explicitly versioned JSON manifest (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestV2 {
	/// Manifest schema version. Always [`ManifestVersion::V2`]; any other
	/// value fails to deserialize.
	#[serde(deserialize_with = "deserialize_v2_version")]
	pub version: ManifestVersion,
	/// Namespace this manifest belongs too.
	pub namespace: Namespace,
	/// Pivot binary configuration and verifiable values.
	pub pivot: PivotConfigV2,
	/// Manifest Set members, by key digest, and threshold.
	pub manifest_set: ManifestSetV2,
	/// Share Set: a tree of threshold groups over the quorum key shares.
	pub share_set: ShareSetV2,
	/// Configuration and verifiable values for the enclave hardware.
	pub enclave: NitroConfig,
	/// DNS resolver configuration for the enclave.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub dns: Option<DnsConfig>,
	/// The digests of the hybrid key whose signed order makes one boot mint
	/// this manifest's app key; the order carries the full key. Absent, the
	/// manifest has no app key.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub app_key_minter: Option<KeyDigests>,
	/// Boot without a quorum key: the enclave starts the pivot once the
	/// manifest set has approved, with no shares and no key forward. The
	/// namespace then names no quorum key and the share set is empty. Absent,
	/// the manifest has a quorum key as usual.
	#[serde(default, skip_serializing_if = "core::ops::Not::not")]
	pub no_quorum_key: bool,
}

/// Accept only `"v2"`. [`ManifestVersion`] doubles as the schema selector for
/// [`super::ManifestBuilder`], so it carries variants a [`ManifestV2`] can
/// never legitimately hold.
fn deserialize_v2_version<'de, D>(
	deserializer: D,
) -> Result<ManifestVersion, D::Error>
where
	D: serde::Deserializer<'de>,
{
	use serde::{Deserialize, de::Error};

	match ManifestVersion::deserialize(deserializer)? {
		ManifestVersion::V2 => Ok(ManifestVersion::V2),
		other => Err(D::Error::custom(format!(
			"manifest v2 requires version \"v2\", got {other:?}"
		))),
	}
}

/// Explicitly versioned JSON manifest envelope (v2).
#[derive(PartialEq, Eq, Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestEnvelopeV2 {
	/// Encapsulated manifest.
	pub manifest: ManifestV2,
	/// Approvals for [`Self::manifest`] from the manifest set.
	pub manifest_set_approvals: Vec<Approval>,
	/// Approvals for [`Self::manifest`] from the share set.
	pub share_set_approvals: Vec<Approval>,
}
