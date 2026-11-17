# Provision a YubiKey with qos client

This playbook covers provisioning a YubiKey as a manifest set or share set member.

A member key is a post-quantum hybrid key (ML-KEM-1024 + X25519 for encryption,
ML-DSA-87 + Ed25519 for signing). YubiKey PIV slots cannot hold these keys, so
the key is derived instead of stored: its 32-byte master seed is

```text
HKDF-SHA512(salt, response || Argon2id(passphrase, salt),
            "qos_hybrid_yubikey_otp_passphrase_member_seed_v1")
```

where `response` is the YubiKey's 20-byte HMAC-SHA1 answer, from OTP slot 2, to
the challenge `salt`, and Argon2id runs at 64 MiB, 3 passes, 1 lane. The salt is
public and lives in a file beside the member's public key. The slot secret never
leaves the device.

To derive the key you need the YubiKey, the salt file and the passphrase. Losing
any one of them loses the key.

**Why the passphrase.** A YubiKey answers a given salt the same way forever. With
no passphrase, one captured answer, from a compromised laptop or a few seconds
with the device and the salt file, would rebuild the member key for good, with
no PIN to stop it. The passphrase is what that capture still lacks: an attacker
holding an answer must still guess the passphrase, paying Argon2id's cost for
each guess. Choose one of at least 12 characters that is used nowhere else.

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

**What this does**: Asks for the passphrase twice, writes a fresh salt, derives
the member key from the YubiKey and the passphrase, and writes its public key.
Before writing anything, it checks that the device answers the challenge, and
answers it the same way twice.

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
the same standard as the device, but not on the same machine. Never store the
passphrase beside either.

Every command prompts for the passphrase without echo. A script can pass
`--yubikey-passphrase-path <file>` instead. The file must sit on a RAM-backed
volume: a release build of `qos_client` refuses any other, and names how to make
one (an HFS+ `ram://` disk on macOS, a tmpfs or ramfs on Linux). The same rule
covers every plaintext key `qos_client` writes: master seeds, Shamir shares,
reconstructed secrets and decrypted plaintexts.

## 3: Use the key

Every command that takes `--yubikey` also needs `--yubikey-salt-path`, and takes
`--challenge-command` when a device is pinned:

```bash
qos_client approve-manifest --yubikey --yubikey-salt-path ~/path/to/alias.salt ...
qos_client yubikey-public --yubikey-salt-path ~/path/to/alias.salt
```

## Strength of a YubiKey member key

The member key is only as strong as slot 2's 20-byte (160-bit) HMAC-SHA1 secret
together with the passphrase. A quantum attacker brute-forcing the slot secret
against the public member key needs about 2^80 work times the cost of the
passphrase search, which can be below the strength of ML-KEM-1024 and ML-DSA-87.
Slot 2 is only as touch-protected as it was programmed: `qos_client` cannot
check that `--touch` was used. A member that needs the full post-quantum margin
should use a file-held key (`generate-file-key`, `--secret-path`) kept on
offline storage.
