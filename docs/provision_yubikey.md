# Provision a YubiKey with qos client

This playbook covers provisioning a YubiKey as a manifest set or share set member.

A member key is a post-quantum hybrid key (ML-KEM-1024 + X25519 for encryption,
ML-DSA-87 for signing). YubiKey PIV slots cannot hold these keys, so the key is
derived instead of stored: its 32-byte master seed is
`HKDF-SHA512(salt, response, "qos_hybrid_yubikey_otp_member_seed_v1")`, where
`response` is the YubiKey's HMAC-SHA1 answer, from OTP slot 2, to the challenge
`salt`. The salt is public and lives in a file beside the member's public key.
The slot secret never leaves the device.

To derive the key you need both the YubiKey and the salt file. Losing either one
loses the key.

## 1: Program OTP slot 2

**What this does**: Writes a random HMAC-SHA1 secret to slot 2 with touch
required. This is the only write slot 2 ever gets.

```bash
ykman otp info                              # must show "Slot 2: empty"
ykman otp chalresp --touch --generate 2
```

Never reprogram, delete or swap slot 2 afterwards. Doing so destroys every
member key derived from it. `qos_client` refuses to run any challenge command
that would write to or reset the device.

## 2: Provision the member key

**What this does**: Writes a fresh salt, derives the member key from the
YubiKey, and writes its public key. Before writing anything, it checks that the
device answers the challenge, and answers it the same way twice.

```bash
qos_client provision-yubikey \
  --pub-path ~/path/to/alias.pub \
  --yubikey-salt-path ~/path/to/alias.salt
```

Slot 2 answers a long press of about three seconds. A short press fires slot 1
instead.

With more than one YubiKey attached, pin the device:

```bash
  --challenge-command 'ykman --device <serial> otp calculate 2 {challenge}'
```

Share the `.pub` file with the ceremony coordinator. Back up the `.salt` file to
the same standard as the device, but not on the same machine.

## 3: Use the key

Every command that takes `--yubikey` also needs `--yubikey-salt-path`, and takes
`--challenge-command` when a device is pinned:

```bash
qos_client approve-manifest --yubikey --yubikey-salt-path ~/path/to/alias.salt ...
qos_client yubikey-public --yubikey-salt-path ~/path/to/alias.salt
```

## Strength of a YubiKey member key

The member key is only as strong as slot 2's 20-byte (160-bit) HMAC-SHA1 secret.
A quantum attacker brute-forcing that secret against the public member key needs
about 2^80 work, which is below the strength of ML-KEM-1024 and ML-DSA-87. A
member that needs the full post-quantum margin should use a file-held key
(`generate-file-key`, `--secret-path`) kept on offline storage.
