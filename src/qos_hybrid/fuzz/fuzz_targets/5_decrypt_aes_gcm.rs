#![no_main]

use libfuzzer_sys::fuzz_target;
use qos_hybrid::{HybridPair, MASTER_SEED_LEN};

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzSeedData {
	seed: [u8; MASTER_SEED_LEN],
	data: Box<[u8]>,
}

// a made-up symmetric envelope must be refused, never decrypted
fuzz_target!(|input: FuzzSeedData| {
	let pair =
		HybridPair::from_master_seed(&zeroize::Zeroizing::new(input.seed))
			.unwrap();

	assert!(pair.aes_gcm_256_decrypt(&input.data).is_err());
});
