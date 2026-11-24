//! GF(2^8) modulo the AES polynomial x^8 + x^4 + x^3 + x + 1, in constant time with no tables:
//! every operation runs the same instructions whatever its operands.

use crate::SECRET_BYTES;

/// Returns `left · right`: shift and add, with each conditional step turned into a mask.
pub(crate) fn multiply(left: u8, right: u8) -> u8 {
	let mut product = 0u8;
	let mut left = left;
	let mut right = right;
	for _ in 0..8 {
		product ^= left & (right & 1).wrapping_neg();
		let carry = left >> 7;
		left = (left << 1) ^ (0x1b & carry.wrapping_neg());
		right >>= 1;
	}
	product
}

/// Returns the multiplicative inverse, `value^254`, which is 0 for 0.
pub(crate) fn invert(value: u8) -> u8 {
	let square = multiply(value, value);
	let mut result = square;
	let mut power = square;
	for _ in 0..6 {
		power = multiply(power, power);
		result = multiply(result, power);
	}
	result
}

/// Writes into `values` the polynomial with constant term `secret` and the coefficients of degree
/// 1 upwards in `coefficients`, `coefficients.len() / SECRET_BYTES` per byte, evaluated at `x`,
/// byte by byte.
pub(crate) fn evaluate(
	secret: &[u8; SECRET_BYTES],
	coefficients: &[u8],
	x: u8,
	values: &mut [u8; SECRET_BYTES],
) {
	let degree = coefficients.len() / SECRET_BYTES;
	for (position, value) in values.iter_mut().enumerate() {
		let own = &coefficients[position * degree..(position + 1) * degree];
		let mut accumulator = 0u8;
		for coefficient in own.iter().rev() {
			accumulator = multiply(accumulator, x) ^ coefficient;
		}
		*value = multiply(accumulator, x) ^ secret[position];
	}
}

/// Writes into `value` the polynomial through `(xs[i], ys[i])` evaluated at `at`, byte by byte.
///
/// The x-coordinates are distinct and public, so the Lagrange weights depend on no secret.
pub(crate) fn interpolate(
	xs: &[u8],
	ys: &[&[u8; SECRET_BYTES]],
	at: u8,
	value: &mut [u8; SECRET_BYTES],
) {
	debug_assert_eq!(
		xs.len(),
		ys.len(),
		"each x-coordinate has one row of values"
	);
	value.fill(0);
	for (index, (&x, y)) in xs.iter().zip(ys).enumerate() {
		let mut numerator = 1u8;
		let mut denominator = 1u8;
		for (other_index, &other) in xs.iter().enumerate() {
			if other_index != index {
				numerator = multiply(numerator, at ^ other);
				denominator = multiply(denominator, x ^ other);
			}
		}
		let weight = multiply(numerator, invert(denominator));
		for (byte, &share) in value.iter_mut().zip(y.iter()) {
			*byte ^= multiply(share, weight);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn multiply_reference(mut left: u8, mut right: u8) -> u8 {
		let mut product = 0;
		while right != 0 {
			if right & 1 == 1 {
				product ^= left;
			}
			let carry = left & 0x80 != 0;
			left <<= 1;
			if carry {
				left ^= 0x1b;
			}
			right >>= 1;
		}
		product
	}

	#[test]
	fn multiply_matches_the_fips_197_examples() {
		assert_eq!(
			multiply(0x57, 0x83),
			0xc1,
			"FIPS 197 section 4.2 gives {{57}} · {{83}} = {{c1}}"
		);
		assert_eq!(
			multiply(0x57, 0x13),
			0xfe,
			"FIPS 197 section 4.2.1 gives {{57}} · {{13}} = {{fe}}"
		);
	}

	#[test]
	fn multiply_matches_a_branching_reference_on_every_pair() {
		for left in 0..=255u8 {
			for right in 0..=255u8 {
				assert_eq!(
					multiply(left, right),
					multiply_reference(left, right),
					"the masked multiply must agree with schoolbook multiplication at {left} · {right}"
				);
			}
		}
	}

	#[test]
	fn every_nonzero_element_times_its_inverse_is_one() {
		assert_eq!(invert(0), 0, "zero has no inverse and maps to zero");
		for value in 1..=255u8 {
			assert_eq!(
				multiply(value, invert(value)),
				1,
				"value^254 is the inverse of {value} in a field of 256 elements"
			);
		}
	}

	#[test]
	fn interpolation_recovers_a_polynomial_from_any_points_on_it() {
		let secret = [0xA5u8; SECRET_BYTES];
		let coefficients: Vec<u8> =
			(0u8..).take(SECRET_BYTES * 2).map(|index| index ^ 0x3c).collect();
		let mut rows = [[0u8; SECRET_BYTES]; 4];
		for (row, x) in rows.iter_mut().zip(1u8..) {
			evaluate(&secret, &coefficients, x, row);
		}
		let mut value = [0u8; SECRET_BYTES];
		interpolate(&[2, 4, 3], &[&rows[1], &rows[3], &rows[2]], 0, &mut value);
		assert_eq!(
			value, secret,
			"three points fix a degree-2 polynomial, whose value at 0 is the secret"
		);
		interpolate(&[2, 4, 3], &[&rows[1], &rows[3], &rows[2]], 1, &mut value);
		assert_eq!(
			value, rows[0],
			"the same three points predict the fourth point at x = 1"
		);
	}
}
