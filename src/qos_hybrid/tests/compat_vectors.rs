//! Byte-exact vectors pinning `qos_hybrid` key derivation, public key
//! encoding, the hybrid envelope and the ML-DSA-87 + SLH-DSA-SHA2-256s +
//! Ed25519 signature format.
//!
//! Enclaves and clients exchange keys, signatures and ciphertexts produced by
//! this crate, so a dependency upgrade must not change a single byte of
//! output. These vectors were generated with fips203 0.4.3, fips204 0.4.6,
//! fips205 0.5.0, x25519-dalek 2.0.1, ed25519-dalek 2.2.0, sha2 0.10, hkdf
//! 0.12 and aes-gcm 0.10 from a fixed master seed. The SLH-DSA part of
//! `vectors/signature.hex` also verifies under `RustCrypto` `slh-dsa`
//! 0.2.0-rc.5 and `@noble/post-quantum` 0.6. Encryption and signing are
//! randomized, so the envelope and signature vectors pin the formats by
//! decrypting and verifying. If one of these tests fails after an upgrade,
//! the upgrade breaks interoperability: do not regenerate the vectors.

use qos_hybrid::{
	AES_GCM_256_PATH, ED25519_DERIVE_PATH, HybridPair, HybridPublic,
	MASTER_SEED_LEN, ML_DSA_XI_DERIVE_PATH, ML_KEM_D_DERIVE_PATH,
	ML_KEM_Z_DERIVE_PATH, SLH_DSA_PUBLIC_SEED_DERIVE_PATH,
	SLH_DSA_SECRET_PRF_DERIVE_PATH, SLH_DSA_SECRET_SEED_DERIVE_PATH,
	X25519_DERIVE_PATH, derive_secret,
};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

const MESSAGE: &[u8] = b"qos_hybrid compatibility vector";
const SEED: &str =
	"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const DERIVED_ML_KEM_D: &str =
	"614e06d7e09f46aee8e1e65cc148411c61f8944152b8b3fd579b233ed0a51c29";
const DERIVED_ML_KEM_Z: &str =
	"7cfabf192210868bce076dcd1a870271139fe6561b97a330eafff26be5853688";
const DERIVED_X25519: &str =
	"c720a4c9872b12175119e3763f3aa3d5ddc08efa8abd14905611d5d135537b37";
const DERIVED_ML_DSA_XI: &str =
	"117a6e348e800e870a3ed1d7b3f18c0cc8b6936156ff16f4e1912b8ab1731ffe";
const DERIVED_SLH_DSA_SECRET_SEED: &str =
	"b11d09d168542bdc90c473ecd1beb952e06244fa5e1814085b76a91074c9ff0f";
const DERIVED_SLH_DSA_SECRET_PRF: &str =
	"00081cc16b606838e2a289df6853ba562f7067d9649cebb1ff352bf91818dab5";
const DERIVED_SLH_DSA_PUBLIC_SEED: &str =
	"b590070b1974750de61b0f27aa8b037ca7abdfec89706f7e9f53d373804be14b";
const DERIVED_ED25519: &str =
	"271a5e22e0182d3ccbb50c374b9dd772dd1b7c14fb68f47f36e8383c4a5e856a";
const DERIVED_AES_GCM: &str =
	"250d000476a472bf5c779189ed93a02c29c1df1c0c8905b929449dd1eeffe84c";
const PUBLIC_KEY_SHA512: &str = "7f3ad09484a5ae97bba3b19528b7e274a99302f2c36b8bd63d1910f3f3ad6ca503f49194a0a9f6ce60ec8c39f74f0ee86e3a35ecf5c6f508efccc7405ce7f51b";
const ATTESTATION_BINDING: &str = "0fdc40ad8e078458df301a091301470a43a1560ec3ba2b0727230d9cba2750c590d3baa7d6dc4289d383a0c816eea652d99ba6bcaebb44034b715bf6bffebb81";
const ASYMMETRIC_ENVELOPE: &str = "68471d2204a2c3efea3f1997ac28d61538346ce7f44bbf18c0bad8069f7dfad2deffd0a42d8f598f67288e7500662de270005f14ce7b72d6449b34289d94c0c348435514400e8b2d6dc52bee304465f88730df0ea6555253920a06927806a6a177b838f64b009986094eb33f94bf59e81220470ec5847f2b83cf73e1a5307c716ca00da50b81ce2021cb9ff1c856f4136a70e2c3448ebf0598d5e67d866dfecfe2f44e97aa5ede65dc033b0e2d51b98fa0df6a947d2e3caea503b5d327e30ba045fdcf99b375fac20b27522ec48f542b25c196711d17a3ea5e62115593fc3b76b277ee31f1c092a26d004a292426d0fcf96d63a4bf7c70a09b7403c7ce61b978a254e4dbc0d70af445cb2e57a67d754b20d7d3acb4c3894fff3f2d5a451befe3d10f387891030434753655c25b4a023dbf639536ac930e7f9b706b7eb6a6d61e842eaba53c7035dff91e50eae737281fd782caf800a917ec57599ed2416cff216d046e7ce88e2821c37a18c8e46daacc69fa0734a38d0ca3c1d23d8afc933c6ce2d28fc8c10520995656fbe9f940ab21389c7d6a9b3f29fd179f67a2903a7b1b5c79583921067ac3f9fc2a69a07080c73d5e5fe3f704645b9811e64fbab7ddd627e4a81b0b3134bb436e1d05aa2a6973ac8b7faeab61b4455b09b878ebb0ab12e36600c4de3f4c8623c89038299fd0319d994b22becaadebc513a41606dcbe1e794d20f302026fa6e28ea2df4f766e0f84d570c06dc58dba531e5973300a8090025d32dfcf3fd82c262ecd9752478c2f9c1045249dbec26e920eea8eeb84f3a1a65c2655b5a952028b38f6cf06cd7125cdc6fc91592d3c489fa4ce7cde43ae14279c172c3b3d696f7d4b33497c0b4dd96c560b36730b764b22b504cb137c08db35004f1e67fafce82676b644d02ff991daf884f4ee090059f0603c53a40d8b80de2d112ad4db6d36c70da3c4a7028e4e7a8ea27f5218a11e9010869ba20feee66c87e80ad1c41eb74f20f88b1f34f876020d5f3b1c169e8f46eea08bc7f29012a1259507127b98d2b6bc4f051f00e9252a7d993838471d0af8314daced3b3e4df8fdee0be24e53f7236b5a5906a5695827277a763a11eed4a52b5c7ea4698c7fc877e66451249c2a07b0b8187f8465eb693f818e53782133fee8bbc975b04b21823be00c3d5733852310cc2ba13cd34de0800de5d68fe715ed68db8c91be68cb6b0c67a8747a4564520c399748d7e9b65742554ffadb1c3788b768a2edc3d8d73011f16e55a3c4de0dd7c86468b440693ab004603454a315dcdee9425e3dcc5d985e313cd3602fd2b9a66b073e0a81d307c8a7feb3ed61558889f26776124933b80c66f4a16849d497688f054444d6a8c443e3890c6c98a3c43c135e88d18f61ec24b6adb4a2f0defc465241c291b3543b895f4a3f3a0d273007a1c989438dbca1889a1f1ee27335b7bd20fdf0d9341569ec8fa2ae85bed6e370746a283d28084540edbfd2b128aee4b922ced33f67db4299e783c477ca6b93a17903a11dd645c0f2b7642f89f1846b4c85dcd37c778800f69fe1c8a0ef792a23bc6dab8036a5dcf725f5b655a591e45b88487b99b850848be04238b364613723bc916f30da63e0032bf01c360bdb44d91207c0644dcf3b3ef360c2c3dceed5eecb7da841a4fb43d42b29dd6546c952fb8b8fe0cf026d3d64d8f072a85b48139fbbecdadcba4a7d5fe6758bff43c0127e63be6838795f2a5bd45a469a0925315f2eec16739c4c9493d642a601e7ba4a1c32facf81de9e38550e087d2fe102c9cab99e755fb8f4f81b5c1c2cfdd424555d8c80b5b9c94277b6ecb50c95c407c6663ed94fb6b804939e322069bfe4e09fbccdae3b43b0bcf94f0548228678418358442396b8542b811af0bade036beb8c3d444eb713fb1de974c5b9ed2349991c2dfaddf91124e28a65a7709a8766b8522bdde946e3b1aa6d950b3e28cde34698e27d405a075c2f86d83aebfed2a5e6baefd2ba88c9547313914fedc87afae96e7c5de05043561b1ce10cecbce75224ee4a824a728e0eb9f19f785fea32cfa974c77a55a24f9d9c2b2569a4e14f65d63ecdea35fadef586d6937a3db652c155c1c8f8ac42f318a0b3cdd0307437760eee6721b2792550f9d093eb9b32ff30eee28ff0362e3f28f8fb123dbadb7f5540a6a3a404aa66b016d5190d38f880340ef62ead682716db9ff3d4c317029ff9a68111b808a94d4bd94125b9f50dd59322c4a741b1f69df4368b124f732d69ff37a93ee8902f0000005523f564165f7bb96815baf4d3fbeb4dbfd9b1e22c03ea7894bf4945f67472b30089f3601ed9f3346897e0e0fbf8ef";
const SIGNATURE: &str = include_str!("vectors/signature.hex");
const SYMMETRIC_ENVELOPE: &str = "f3dd99e86fbcfbe2b63dd35d2f000000f1f3e400d426f693e45c206c2be8a904a485dba75e14fafdd5c45e146761b09d51719cc573a53b094f18e06eea7b40";

fn seed() -> Zeroizing<[u8; MASTER_SEED_LEN]> {
	let mut seed = Zeroizing::new([0u8; MASTER_SEED_LEN]);
	qos_hex::decode_to_buf(SEED, &mut *seed).unwrap();
	seed
}

fn pair() -> HybridPair {
	HybridPair::from_master_seed(&seed()).unwrap()
}

#[test]
fn master_seed_derivation_is_pinned() {
	for (path, expected) in [
		(ML_KEM_D_DERIVE_PATH, DERIVED_ML_KEM_D),
		(ML_KEM_Z_DERIVE_PATH, DERIVED_ML_KEM_Z),
		(X25519_DERIVE_PATH, DERIVED_X25519),
		(ML_DSA_XI_DERIVE_PATH, DERIVED_ML_DSA_XI),
		(SLH_DSA_SECRET_SEED_DERIVE_PATH, DERIVED_SLH_DSA_SECRET_SEED),
		(SLH_DSA_SECRET_PRF_DERIVE_PATH, DERIVED_SLH_DSA_SECRET_PRF),
		(SLH_DSA_PUBLIC_SEED_DERIVE_PATH, DERIVED_SLH_DSA_PUBLIC_SEED),
		(ED25519_DERIVE_PATH, DERIVED_ED25519),
		(AES_GCM_256_PATH, DERIVED_AES_GCM),
	] {
		assert_eq!(
			qos_hex::encode(&derive_secret(&seed(), path).unwrap()[..]),
			expected,
			"derive path {}",
			String::from_utf8_lossy(path)
		);
	}
}

#[test]
fn public_key_and_attestation_binding_are_pinned() {
	let public = pair().public_key();

	assert_eq!(
		qos_hex::encode(&Sha512::digest(public.to_bytes())),
		PUBLIC_KEY_SHA512
	);
	assert_eq!(
		qos_hex::encode(&public.attestation_binding()),
		ATTESTATION_BINDING
	);
	assert!(HybridPublic::from_bytes(&public.to_bytes()).unwrap() == public);
}

#[test]
fn pinned_asymmetric_envelope_decrypts() {
	let envelope = qos_hex::decode(ASYMMETRIC_ENVELOPE).unwrap();

	assert_eq!(&pair().decrypt(&envelope).unwrap()[..], MESSAGE);
}

#[test]
fn pinned_signature_verifies() {
	let signature = qos_hex::decode(SIGNATURE).unwrap();

	assert!(pair().public_key().verify(MESSAGE, &signature).is_ok());
}

#[test]
fn pinned_symmetric_envelope_decrypts() {
	let envelope = qos_hex::decode(SYMMETRIC_ENVELOPE).unwrap();

	assert_eq!(&pair().aes_gcm_256_decrypt(&envelope).unwrap()[..], MESSAGE);
}
