//! Pure-`std` SHA-384 (the SHA-512 core truncated to 384 bits) plus the
//! canonical `"sha384:<lowercase-hex>"` formatter used across the runtime.
//!
//! This crate's `Cargo.toml` does not wire in the `sha2`/`hex` crates, and the
//! build forbids adding external dependencies, so the digest is implemented
//! here with `std` only. Output is byte-for-byte identical to the rest of the
//! runtime's `sha384_hex` helpers (verified against FIPS-180-4 test vectors in
//! the unit tests below). No `unsafe`, no randomness, no clock.

/// SHA-512 round constants (also used by SHA-384).
const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// SHA-384 initial hash values (FIPS-180-4 §5.3.4).
const H0: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

/// Compute the raw 48-byte SHA-384 digest of `bytes`.
pub fn sha384(bytes: &[u8]) -> [u8; 48] {
    let mut h = H0;

    // Pre-processing: pad the message.
    let bit_len = (bytes.len() as u128) * 8;
    let mut msg = bytes.to_vec();
    msg.push(0x80);
    // Pad with zeros until length ≡ 112 (mod 128).
    while msg.len() % 128 != 112 {
        msg.push(0);
    }
    // Append the 128-bit big-endian message length in bits.
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 1024-bit (128-byte) block.
    for block in msg.chunks_exact(128) {
        let mut w = [0u64; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&block[i * 8..i * 8 + 8]);
            *word = u64::from_be_bytes(buf);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1)
                ^ w[i - 15].rotate_right(8)
                ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19)
                ^ w[i - 2].rotate_right(61)
                ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    // SHA-384 output is the first six 64-bit words (48 bytes).
    let mut out = [0u8; 48];
    for (i, word) in h.iter().take(6).enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Lowercase hex encoding of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(LUT[(b >> 4) as usize] as char);
        s.push(LUT[(b & 0x0f) as usize] as char);
    }
    s
}

/// SHA-384 digest of `bytes`, formatted as `"sha384:<lowercase-hex>"`.
///
/// Matches the canonical hash convention shared across the runtime's receipt
/// spine (`sha384:` prefix + 96 hex chars).
pub fn sha384_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity("sha384:".len() + 96);
    s.push_str("sha384:");
    s.push_str(&hex(&sha384(bytes)));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abc_vector() {
        // FIPS-180-4 SHA-384("abc")
        assert_eq!(
            hex(&sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn two_block_vector() {
        // FIPS-180-4 SHA-384 of the 112-char message (forces two blocks).
        let msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assert_eq!(
            hex(&sha384(msg.as_bytes())),
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
             fcc7c71a557e2db966c3e9fa91746039"
        );
    }

    #[test]
    fn formatter_prefix_and_len() {
        let h = sha384_hex(b"hello");
        assert!(h.starts_with("sha384:"));
        assert_eq!(h.len(), "sha384:".len() + 96);
    }

    #[test]
    fn deterministic() {
        assert_eq!(sha384_hex(b"x"), sha384_hex(b"x"));
        assert_ne!(sha384_hex(b"x"), sha384_hex(b"y"));
    }
}
