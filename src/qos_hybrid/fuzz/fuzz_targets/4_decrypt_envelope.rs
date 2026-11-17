#![no_main]

use libfuzzer_sys::fuzz_target;
use qos_hybrid::{HybridPair, MASTER_SEED_LEN};

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzSeedData {
	seed: [u8; MASTER_SEED_LEN],
	data: Box<[u8]>,
}

// the enclave decrypts host-supplied envelopes (shares, forwarded keys): a
// made-up envelope must be refused, never decrypted and never a panic
fuzz_target!(|input: FuzzSeedData| {
	let pair =
		HybridPair::from_master_seed(&zeroize::Zeroizing::new(input.seed))
			.unwrap();

	assert!(pair.decrypt(&input.data).is_err());
});
