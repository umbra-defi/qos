# QOS Hybrid Key Set Specification

This document specifies the key schemes of `qos_hybrid`, the post-quantum key
set this fork of QuorumOS uses for the quorum key, the ephemeral keys and the
quorum members' keys. The canonical implementation is this crate; the pinned
vectors in `tests/compat_vectors.rs` are normative.

Every scheme is a hybrid of post-quantum and classical primitives, and holds
while any one of them does:

1. **Signing**: ML-DSA-87 (FIPS 204), SLH-DSA-SHA2-256s (FIPS 205) and Ed25519
   (RFC 8032), all three required. The two post-quantum schemes rest on
   unrelated assumptions: module lattices, and the hash function alone.
2. **Encryption**: ML-KEM-1024 (FIPS 203) and X25519 (RFC 7748), combined
   through HKDF-SHA512 into AES-256-GCM.
3. **Symmetric**: AES-256-GCM.

`||` is byte concatenation. Every length is in bytes.

## 1. Master seed and key derivation

A key set derives from one 32-byte master seed. Shamir sharding of the quorum
key shares this seed.

```text
DERIVE(seed, path) = HKDF-SHA512-Expand(HKDF-SHA512-Extract(salt = path, ikm = seed), info = "", L = 32)
```

| Secret | Derive path | Use |
| --- | --- | --- |
| ML-KEM-1024 `d` | `qos_hybrid_ml_kem_1024_d` | `ML-KEM.KeyGen_internal(d, z)` |
| ML-KEM-1024 `z` | `qos_hybrid_ml_kem_1024_z` | as above |
| X25519 secret | `qos_hybrid_x25519` | clamped per RFC 7748 |
| ML-DSA-87 `xi` | `qos_hybrid_ml_dsa_87_xi` | `ML-DSA.KeyGen_internal(xi)` |
| SLH-DSA `SK.seed` | `qos_hybrid_slh_dsa_sha2_256s_sk_seed` | `SLH-DSA.KeyGen_internal(SK.seed, SK.prf, PK.seed)` |
| SLH-DSA `SK.prf` | `qos_hybrid_slh_dsa_sha2_256s_sk_prf` | as above |
| SLH-DSA `PK.seed` | `qos_hybrid_slh_dsa_sha2_256s_pk_seed` | as above |
| Ed25519 seed | `qos_hybrid_ed25519` | RFC 8032 secret key |
| AES-256-GCM key | `qos_hybrid_aes_gcm_256` | the symmetric scheme |

## 2. Public key

```text
public_key = ml_kem_1024_encapsulation_key (1568)
          || x25519_public                  (32)
          || ml_dsa_87_public               (2592)
          || slh_dsa_sha2_256s_public       (64)
          || ed25519_public                 (32)        = 4288 bytes
```

A decoder refuses any other length, an ML-KEM-1024 key that fails the FIPS 203
modulus check, an ML-DSA-87 key that fails to decode, and an Ed25519 key that
does not decompress or has small order. Any 64 bytes are an SLH-DSA-SHA2-256s
public key (`PK.seed || PK.root`).

### Attestation binding

A 4288-byte key does not fit in a Nitro attestation document's `public_key`
field (the NSM request is capped at 4096 bytes). Wherever a key is attested,
the document and the manifest PCR commitments carry its binding instead:

```text
attestation_binding = SHA-512("qos_hybrid_attestation_binding_v1" || public_key)   (64)
```

A verifier receives the full key beside the document and checks it against the
binding before using it.

## 3. Signing

```text
DOMAIN = "qos_hybrid_ml_dsa_87_slh_dsa_sha2_256s_ed25519_v1"
M'     = 0x00 || len(DOMAIN) || DOMAIN || message

SIGN(message):
  rnd       = 32 fresh random bytes
  ml_dsa    = ML-DSA-87.Sign_internal(sk, M', rnd)                    (hedged; 4627)
  opt_rand  = 32 fresh random bytes
  slh_dsa   = SLH-DSA-SHA2-256s.Sign_internal(sk, M', opt_rand)       (hedged; 29792)
  ed25519   = Ed25519.Sign(sk, DOMAIN || message)                     (64)
  return ml_dsa || slh_dsa || ed25519                                 (34483)

VERIFY(message, signature):
  require len(signature) == 34483
  require ML-DSA-87.Verify(pk, message, signature[0..4627], ctx = DOMAIN)
  require SLH-DSA-SHA2-256s.Verify(pk, message, signature[4627..34419], ctx = DOMAIN)
  require Ed25519.VerifyStrict(pk, DOMAIN || message, signature[34419..34483])
```

All three parts must verify. `DOMAIN` is the ML-DSA-87 and SLH-DSA context
string and the prefix of the message Ed25519 signs, so no part verifies as a
plain signature of its scheme, and none can be lifted into another protocol.
ML-DSA-87 and SLH-DSA signatures are hedged, so two signatures over one message
differ.

## 4. Public key encryption

```text
ENCRYPT(receiver_public, message):
  (ss_kem, ct) = ML-KEM-1024.Encaps(receiver.ml_kem, m = 32 fresh random bytes)        (32, 1568)
  e            = fresh X25519 secret;  E = X25519(e, 9)
  ss_x         = X25519(e, receiver.x25519)          ; refuse an all-zero result
  transcript   = SHA-512(E || ct || receiver.ml_kem || receiver.x25519)                (64)
  key          = HKDF-SHA512(salt = "qos_hybrid_ml_kem_1024_x25519_combiner_v1",
                             ikm  = ss_kem || ss_x,
                             info = transcript, L = 32)
  nonce        = 12 fresh random bytes
  c            = AES-256-GCM(key, nonce, message, aad = transcript)
  return borsh(Envelope { nonce[12], E[32], ct[1568], c: Vec<u8> })
```

Decryption decapsulates `ct`, recomputes the X25519 secret from `E`, refuses an
all-zero X25519 result, rebuilds the transcript from its own public key and
decrypts. Every transcript field has a fixed length, so the concatenation needs
no length prefixes.

## 5. Symmetric encryption

```text
ENCRYPT(message):
  nonce = 12 fresh random bytes
  c     = AES-256-GCM(aes_key, nonce, message, aad = "qos_hybrid_aes_gcm_256_symmetric")
  return borsh(SymmetricEnvelope { nonce[12], c: Vec<u8> })
```

## 6. YubiKey member keys

A member key held on a YubiKey is not stored; `qos_client` derives its master
seed from OTP slot 2 (HMAC-SHA1 challenge-response) and a passphrase:

```text
pk_key = Argon2id(passphrase, salt, m = 65536 KiB, t = 3, p = 1, L = 32)
seed   = HKDF-SHA512(salt = salt,
                     ikm  = response || pk_key,
                     info = "qos_hybrid_yubikey_otp_passphrase_member_seed_v1", L = 32)
```

`salt` is a public 32-byte value stored beside the member's public key, and
`response` is the device's 20-byte answer to the challenge `salt`. See
`docs/provision_yubikey.md` for the operator flow.
