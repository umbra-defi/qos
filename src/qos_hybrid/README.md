# `qos_hybrid`

Post-quantum hybrid keys for `QuorumOS`: the quorum key, the ephemeral keys and
the quorum members' keys.

One 32-byte master seed derives, through HKDF-SHA512, an ML-KEM-1024 key, an
X25519 key, an ML-DSA-87 key, an Ed25519 key and an AES-256-GCM secret.

- **Encryption** encapsulates to both ML-KEM-1024 and X25519, combines both
  shared secrets with HKDF-SHA512 over the full transcript, and seals the
  message with AES-256-GCM. A message stays confidential while either
  ML-KEM-1024 or X25519 holds.
- **Signing** signs with both ML-DSA-87 (FIPS 204, hedged with fresh
  randomness) and Ed25519, and a signature verifies only if both halves do. A
  signature stays unforgeable while either ML-DSA-87 or Ed25519 holds.
- **Attestation** binds a key by its 64-byte SHA-512 binding digest
  ([`HybridPublic::attestation_binding`]), since the 4224-byte public key does
  not fit in a Nitro attestation document's `public_key` field.

Shamir sharding of the master seed is unchanged from upstream QuorumOS's
P-256 key set: shares are still shares of a 32-byte seed. See
[SPEC.md](SPEC.md) for the byte-level specification.
