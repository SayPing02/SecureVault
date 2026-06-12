// Shamir's Secret Sharing
//
// The basic idea: hide the secret as the constant term of a random polynomial.
// Give each person a different point on the polynomial. You need k points
// to figure out the polynomial (and get the secret back), but k-1 points
// tell you nothing. Pretty cool actually.
//
// We only split the AES key (32 bytes), not the whole file. Each byte
// gets its own polynomial so the shares stay small.

use crate::core::gf256;
use crate::core::error::{CoreError, CoreResult};
use rand::RngCore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub x: u8, // which point on the polynomial (1, 2, 3...)
    pub y: Vec<u8>, // the y values, one per secret byte
}

// Split a secret into n shares where any k can reconstruct it
pub fn split(secret: &[u8], n: u8, k: u8) -> CoreResult<Vec<Share>> {
    validate_params(n, k)?;
    if secret.is_empty() {
        return Err(CoreError::Shamir("cannot split empty secret".into()));
    }

    let mut rng = rand::thread_rng();

    // create empty shares with x = 1, 2, 3, ... n
    let mut shares: Vec<Share> = (1..=n)
        .map(|x| Share {
            x,
            y: vec![0u8; secret.len()],
        })
        .collect();

    // for each byte of the secret, create a random polynomial
    // with that byte as the constant term, then evaluate at each x
    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        let mut coeffs = vec![0u8; k as usize];
        coeffs[0] = secret_byte;
        for coeff in coeffs.iter_mut().skip(1) {
            *coeff = random_nonzero(&mut rng);
        }

        for share in shares.iter_mut() {
            share.y[byte_idx] = gf256::poly_eval(&coeffs, share.x);
        }
    }

    Ok(shares)
}

// Reconstruct the secret from k or more shares using Lagrange interpolation
pub fn combine(shares: &[Share]) -> CoreResult<Vec<u8>> {
    if shares.len() < 2 {
        return Err(CoreError::Shamir("need at least 2 shares".into()));
    }

    let secret_len = shares[0].y.len();
    if shares.iter().any(|s| s.y.len() != secret_len) {
        return Err(CoreError::Shamir("shares have different lengths".into()));
    }

    // check for duplicate x values - would break interpolation
    let xs: Vec<u8> = shares.iter().map(|s| s.x).collect();
    for i in 0..xs.len() {
        for j in (i + 1)..xs.len() {
            if xs[i] == xs[j] {
                return Err(CoreError::Shamir(
                    format!("duplicate x coordinate: {}", xs[i])
                ));
            }
        }
    }

    // interpolate each byte position independently
    let mut secret = vec![0u8; secret_len];
    for byte_idx in 0..secret_len {
        secret[byte_idx] = interpolate_at_zero(shares, byte_idx);
    }

    Ok(secret)
}

// Lagrange interpolation at x=0 for one byte position
// this gives us p(0) which is the secret
fn interpolate_at_zero(shares: &[Share], byte_idx: usize) -> u8 {
    let mut result = 0u8;

    for (i, share_i) in shares.iter().enumerate() {
        let mut num = 1u8;
        let mut den = 1u8;

        for (j, share_j) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            // in GF(256), 0 - x_j is just x_j (subtraction = addition = XOR)
            num = gf256::mul(num, share_j.x);
            den = gf256::mul(den, gf256::add(share_i.x, share_j.x));
        }

        let lagrange = gf256::div(num, den);
        let term = gf256::mul(lagrange, share_i.y[byte_idx]);
        result = gf256::add(result, term);
    }

    result
}

fn validate_params(n: u8, k: u8) -> CoreResult<()> {
    if n < 2 {
        return Err(CoreError::Shamir("n must be at least 2".into()));
    }
    if k < 2 {
        return Err(CoreError::Shamir("k must be at least 2".into()));
    }
    if k > n {
        return Err(CoreError::Shamir("k can't be bigger than n".into()));
    }
    Ok(())
}

// get a random non-zero byte for polynomial coefficients
fn random_nonzero(rng: &mut impl RngCore) -> u8 {
    loop {
        let mut buf = [0u8; 1];
        rng.fill_bytes(&mut buf);
        if buf[0] != 0 {
            return buf[0];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_split_combine() {
        let secret = b"a 32-byte AES key padding here!!";
        let shares = split(secret, 5, 3).unwrap();
        let recovered = combine(&shares[0..3]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_all_shares_also_works() {
        let secret = b"another secret value to share!!!";
        let shares = split(secret, 6, 4).unwrap();
        let recovered = combine(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_non_contiguous_subset() {
        let secret = b"pick any three of these shares!!";
        let shares = split(secret, 5, 3).unwrap();

        // try shares 1, 3, 5 instead of 1, 2, 3
        let subset = vec![
            shares[0].clone(),
            shares[2].clone(),
            shares[4].clone(),
        ];
        assert_eq!(combine(&subset).unwrap(), secret);
    }

    #[test]
    fn test_too_few_shares_gives_garbage() {
        let secret = b"this should stay hidden for k-1!";
        let shares = split(secret, 5, 3).unwrap();
        let recovered = combine(&shares[0..2]).unwrap();
        assert_ne!(recovered, secret); // should NOT match
    }

    #[test]
    fn test_bad_params() {
        assert!(split(b"x", 3, 5).is_err()); // k > n
        assert!(split(b"x", 1, 1).is_err()); // too small
        assert!(split(b"", 3, 2).is_err()); // empty
    }

    #[test]
    fn test_duplicate_shares_rejected() {
        let secret = b"sixteen byte key";
        let shares = split(secret, 4, 2).unwrap();
        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert!(combine(&dup).is_err());
    }
}
