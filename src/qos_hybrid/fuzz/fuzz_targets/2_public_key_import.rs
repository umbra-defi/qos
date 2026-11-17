#![no_main]

use libfuzzer_sys::fuzz_target;
use qos_hybrid::HybridPublic;

// the enclave parses host-supplied public keys: decoding must never panic, a
// decoded key re-encodes to the same bytes, and nothing verifies against it
// without its private key
fuzz_target!(|data: &[u8]| {
	let Ok(public) = HybridPublic::from_bytes(data) else {
		return;
	};

	assert_eq!(public.to_bytes(), data);
	assert!(
		public.verify(b"a message", &[0; qos_hybrid::SIGNATURE_LEN]).is_err()
	);
});
