#![no_main]

use libfuzzer_sys::fuzz_target;
use qos_hybrid::{HybridPair, MASTER_SEED_LEN};

#[derive(Clone, Debug, arbitrary::Arbitrary)]
pub struct FuzzSeedMessage {
	seed: [u8; MASTER_SEED_LEN],
	message: Box<[u8]>,
}

// every key signs every message, and the signature verifies under its key
fuzz_target!(|input: FuzzSeedMessage| {
	let pair =
		HybridPair::from_master_seed(&zeroize::Zeroizing::new(input.seed))
			.unwrap();
	let signature = pair.sign(&input.message).unwrap();

	assert_eq!(signature.len(), qos_hybrid::SIGNATURE_LEN);
	assert!(pair.public_key().verify(&input.message, &signature).is_ok());
});
