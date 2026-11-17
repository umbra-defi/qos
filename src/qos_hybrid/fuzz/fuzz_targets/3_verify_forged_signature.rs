#![no_main]

use libfuzzer_sys::fuzz_target;
use qos_hybrid::{HybridPair, MASTER_SEED_LEN};

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzSeedSignature {
	seed: [u8; MASTER_SEED_LEN],
	signature: Box<[u8]>,
}

// a signature the fuzzer makes up must never verify, and must never panic
fuzz_target!(|input: FuzzSeedSignature| {
	let pair =
		HybridPair::from_master_seed(&zeroize::Zeroizing::new(input.seed))
			.unwrap();

	assert!(
		pair.public_key()
			.verify(b"a message to authenticate", &input.signature)
			.is_err()
	);
});
