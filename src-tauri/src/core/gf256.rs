// GF(2^8) finite field arithmetic
// Needed for Shamir secret sharing to work properly - regular integer
// math would have rounding issues, but a finite field keeps everything exact.
// Using the same irreducible polynomial as AES: x^8 + x^4 + x^3 + x + 1 (0x11b)
//
// I learned about this from:
// https://en.wikipedia.org/wiki/Finite_field_arithmetic

struct Tables {
    exp: [u8; 512], // doubled so we dont need modulo when adding logs
    log: [u8; 256],
}

// Build the lookup tables once using OnceLock (thread-safe lazy init).
// This way we don't recalculate them every time we do a multiplication.
fn tables() -> &'static Tables {
    use std::sync::OnceLock;
    static TABLES: OnceLock<Tables> = OnceLock::new();

    TABLES.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];

        // 3 is a generator of GF(2^8) - it cycles through all 255
        // non-zero elements. (2 does NOT work as a generator here,
        // it only hits 51 elements which completely breaks everything)
        let mut x: u16 = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;

            // multiply x by 3: in GF(2^8), 3*x = (2*x) XOR x
            // the shift is done in u16 to avoid overflow
            let mut doubled = x << 1;
            if doubled & 0x100 != 0 {
                doubled ^= 0x11b; // reduce mod the polynomial
            }
            x = (doubled ^ x) & 0xff;
        }

        // copy first half into second half so we can just do
        // exp[log[a] + log[b]] without worrying about wrapping
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }

        Tables { exp, log }
    })
}

// addition in GF(2^8) is just XOR
pub fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

// multiplication using log/exp tables
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    let sum = t.log[a as usize] as usize + t.log[b as usize] as usize;
    t.exp[sum]
}

// division: a / b
pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "division by zero in GF(256)");
    if a == 0 {
        return 0;
    }
    let t = tables();
    // add 255 to avoid going negative
    let idx = t.log[a as usize] as usize + 255 - t.log[b as usize] as usize;
    t.exp[idx]
}

// evaluate polynomial at point x using Horner's method
// coeffs[0] = constant term (the secret in shamir), coeffs[1] = x coeff, etc
pub fn poly_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = add(mul(result, x), c);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul_commutative() {
        // a * b should always equal b * a
        for a in 0u8..=255 {
            for b in 0u8..=255 {
                assert_eq!(mul(a, b), mul(b, a));
            }
        }
    }

    #[test]
    fn test_div_inverts_mul() {
        for a in 0u8..=255 {
            for b in 1u8..=255 {
                let product = mul(a, b);
                assert_eq!(div(product, b), a);
            }
        }
    }

    #[test]
    fn test_add_is_xor() {
        assert_eq!(add(0xAB, 0xCD), 0xAB ^ 0xCD);
        assert_eq!(add(42, 42), 0); // x + x = 0 in GF(2^n)
    }

    #[test]
    fn test_poly_eval() {
        // constant polynomial should just return the constant
        assert_eq!(poly_eval(&[99], 7), 99);
        assert_eq!(poly_eval(&[99], 0), 99);
    }
}
