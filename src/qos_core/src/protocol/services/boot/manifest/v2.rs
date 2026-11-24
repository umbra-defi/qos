//! Explicitly versioned JSON manifest schema (v2).

use std::net::IpAddr;

use crate::protocol::{
	Hash256,
	services::boot::{
		Approval, BridgeConfig, ManifestSet, Namespace, NitroConfig, PivotEnv,
		QuorumMember, RestartPolicy, ShareGroup, ShareNode, ShareSet,
	},
};

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

/// The share set of a v2 manifest: the root of a share tree. It recovers the
/// quorum key once `threshold` of its children are satisfied, its members
/// first, then its groups. With no groups it serializes exactly as a flat
/// [`ShareSet`], so flat manifests keep their hash.
#[derive(
	PartialEq, Eq, Debug, Clone, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShareSetV2 {
	/// Children that must be satisfied to recover the quorum key.
	#[serde(with = "qos_json::string_or_numeric")]
	pub threshold: u32,
	/// Members holding a share of the quorum key.
	pub members: Vec<QuorumMember>,
	/// Groups, each recovering one share of the quorum key.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub groups: Vec<ShareGroup>,
}

impl ShareNode for ShareSetV2 {
	fn threshold(&self) -> u32 {
		self.threshold
	}
	fn members(&self) -> &[QuorumMember] {
		&self.members
	}
	fn groups(&self) -> &[ShareGroup] {
		&self.groups
	}
}

impl From<ShareSet> for ShareSetV2 {
	fn from(flat: ShareSet) -> Self {
		Self {
			threshold: flat.threshold,
			members: flat.members,
			groups: vec![],
		}
	}
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
	/// Manifest Set members and threshold.
	pub manifest_set: ManifestSet,
	/// Share Set: a tree of threshold groups over the quorum key shares.
	pub share_set: ShareSetV2,
	/// Configuration and verifiable values for the enclave hardware.
	pub enclave: NitroConfig,
	/// DNS resolver configuration for the enclave.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub dns: Option<DnsConfig>,
	/// Hybrid public key whose signed order makes one boot mint this
	/// manifest's app key. Absent, the manifest has no app key.
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		with = "qos_hex::serde::option"
	)]
	pub app_key_minter: Option<Vec<u8>>,
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
