//! This file implements the fuzzy commitment of a biometric vector (enrollment and authentication),
//! which derives a secret key K and reconstructs it bit for bit.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public helper data, safe to store or transmit
/// # Fields
/// grid_offsets: per-dimension offsets - bring each value back to the center of its quantization cell
/// commitment_mask: per-dimension error-correction mask - used to correct errors during authentication
/// key_verification_tag: SHA-256 hash of the secret key K, used to verify the reconstruction during authentication
#[derive(Clone, Debug, Zeroize)]
pub struct FuzzyHelperData {
    pub grid_offsets: Vec<f32>,
    pub commitment_mask: Vec<u8>,
    pub key_verification_tag: [u8; 32],
}

/// Enrollment result containing the secret key K (zeroized on drop)
/// # Fields
/// secret_key: 32-byte secret key K (zeroized on drop)
/// helper_data: public helper data used for authentication (not zeroized)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EnrollmentOutput {
    pub secret_key: [u8; 32],
    #[zeroize(skip)]
    pub helper_data: FuzzyHelperData,
}

/// Quantization step used before Gray coding
/// Width of a quantization cell for each dimension of the biometric vector
/// Each dimension is mapped to a cell number
/// # Example
/// * QUANT_STEP = 0.05 means that each dimension of the biometric vector is quantized in steps of 0.05
const QUANT_STEP: f32 = 0.05;

/// Position of the cell center, as a fraction of the cell width
const HALF_CELL: f32 = 0.5;

/// Origin of the quantization grid (lower bound of cell 0)
const GRID_ORIGIN: f32 = -2.0;

/// Converts a binary integer to Gray code
/// XOR between the number and itself shifted right by 1 bit
/// # Argument
/// * `n` - binary integer (0-255)
/// # Returns
/// * corresponding Gray-coded integer (0-255)
#[inline]
fn binary_to_gray(n: u8) -> u8 {
    n ^ (n >> 1)
}

/// Hamming (7,4) encoding of a 4-bit nibble into a 7-bit codeword with parity bits for error correction
/// # Arguments
/// * `d` - 4-bit nibble (half byte) (0-15)
/// # Returns
/// * 7-bit codeword (0-127) with parity bits for error correction
/// # Example
/// * d = 0b1010 (10)
/// * d0 = 0, d1 = 1, d2 = 0, d3 = 1
/// * p0 = d0 ^ d1 ^ d3 = 0 ^ 1 ^ 1 = 0
/// * p1 = d0 ^ d2 ^ d3 = 0 ^ 0 ^ 1 = 1
/// * p2 = d1 ^ d2 ^ d3 = 1 ^ 0 ^ 1 = 0
/// * codeword = 0b0100101 (p0 p1 d0 p2 d1 d2 d3)
#[inline]
fn hamming74_encode_nibble(d: u8) -> u8 {
    // Extract the data bits d0, d1, d2, d3 from the nibble d
    let d0 = (d >> 0) & 1;
    let d1 = (d >> 1) & 1;
    let d2 = (d >> 2) & 1;
    let d3 = (d >> 3) & 1;
    // Compute the parity bits p0, p1, p2 using the Hamming (7,4) formulas
    let p0 = d0 ^ d1 ^ d3;
    let p1 = d0 ^ d2 ^ d3;
    let p2 = d1 ^ d2 ^ d3;
    // Assemble the 7-bit codeword (p0 p1 d0 p2 d1 d2 d3)
    (p0 << 0) | (p1 << 1) | (d0 << 2) | (p2 << 3) | (d1 << 4) | (d2 << 5) | (d3 << 6)
}

/// Hamming (7,4) decoding of a 7-bit codeword into a 4-bit nibble with error correction
/// # Arguments
/// * `cw` - 7-bit codeword (0-127) with parity bits for error correction
/// # Returns
/// * 4-bit nibble (0-15) after error correction
/// # Example
/// * cw = 0b0100101 (p0 p1 d0 p2 d1 d2 d3)
/// * b0 = 0, b1 = 1, b2 = 0, b3 = 0, b4 = 1, b5 = 0, b6 = 1
/// * s0 = b0 ^ b2 ^ b4 ^ b6 = 0 ^ 0 ^ 1 ^ 1 = 0
/// * s1 = b1 ^ b2 ^ b5 ^ b6 = 1 ^ 0 ^ 0 ^ 1 = 0
/// * s2 = b3 ^ b4 ^ b5 ^ b6 = 0 ^ 1 ^ 0 ^ 1 = 0
/// * syndrome = 0b000 = 0 (no error)
/// * d0 = b2 = 0, d1 = b4 = 1, d2 = b5 = 0, d3 = b6 = 1
/// * nibble = 0b1010 (10)
#[inline]
fn hamming74_decode_nibble(mut cw: u8) -> u8 {
    // Extract the bits of the 7-bit codeword (b0 to b6)
    let b0 = (cw >> 0) & 1;
    let b1 = (cw >> 1) & 1;
    let b2 = (cw >> 2) & 1;
    let b3 = (cw >> 3) & 1;
    let b4 = (cw >> 4) & 1;
    let b5 = (cw >> 5) & 1;
    let b6 = (cw >> 6) & 1;
    // Compute the syndrome to detect and correct a single error
    let s0 = b0 ^ b2 ^ b4 ^ b6;
    let s1 = b1 ^ b2 ^ b5 ^ b6;
    let s2 = b3 ^ b4 ^ b5 ^ b6;
    let syndrome = s0 | (s1 << 1) | (s2 << 2);
    // Correct a single error if the syndrome is non-zero (1 to 7)
    if syndrome > 0 && syndrome <= 7 {
        cw ^= 1 << (syndrome - 1);
    }
    // Retrieve the data bits d0, d1, d2, d3 after correction
    let d0 = (cw >> 2) & 1;
    let d1 = (cw >> 4) & 1;
    let d2 = (cw >> 5) & 1;
    let d3 = (cw >> 6) & 1;
    // Rebuild the 4-bit nibble from the corrected data bits
    d0 | (d1 << 1) | (d2 << 2) | (d3 << 3)
}

/// Helper function computing the center of a cell
/// # Arguments
/// * idx: cell number
/// # Returns
/// * Center of the cell
fn find_cell_center(idx: i32) -> f32 {
    (idx as f32 + HALF_CELL) * QUANT_STEP + GRID_ORIGIN
}

/// Generates the offsets that bring each value back to the center of its cell
/// # Arguments
/// * face_master: vector of floats (biometric data)
/// # Returns
/// * Vector of per-dimension offsets
fn generate_grid_offsets(face_master: &[f32]) -> Vec<f32> {
    let mut grid_offsets = Vec::with_capacity(face_master.len());
    for &val in face_master.iter() {
        // base_idx: number of the cell containing val
        let base_idx = ((val - GRID_ORIGIN) / QUANT_STEP) as i32;
        // cell_center: center of the cell containing val (cell number = base_idx)
        let cell_center = find_cell_center(base_idx);
        // val - cell_center: offset bringing val back to the center of its quantization cell
        grid_offsets.push(val - cell_center);
    }
    grid_offsets
}

/// Quantizes a vector of floats into Gray code, with a per-dimension offset
/// # Arguments
/// * `vector` - vector of floats to quantize
/// * `offsets` - per-dimension offsets bringing the values back to the center of their quantization cell
/// # Returns
/// * vector of Gray-coded quantized bytes
fn quantize_to_gray(vector: &[f32], offsets: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(vector.len());
    // val: float value of dimension i of the biometric vector
    for (i, &val) in vector.iter().enumerate() {
        // Offset (off) for dimension i, or 0.0 if not provided
        let off = offsets.get(i).copied().unwrap_or(0.0);
        // Shift (back to the center of the cell)
        // val - off: value centered in its quantization cell
        // - GRID_ORIGIN: translation, assuming values are always > GRID_ORIGIN
        // / QUANT_STEP: quantization in steps of QUANT_STEP to obtain an index
        // shifted: quantized float value before conversion to an integer
        let shifted = (val - off - GRID_ORIGIN) / QUANT_STEP;
        // Quantization to a u8 integer (0 to 255) before Gray conversion
        // idx: quantized cell index/number as a u8 (0-255) for dimension i
        let idx = if shifted < 0.0 {
            0u8
        } else if shifted > 255.0 {
            255u8
        } else {
            shifted as u8
        };
        // Push the Gray code of the quantized index to the output vector
        out.push(binary_to_gray(idx));
    }
    out
}

// Derives the secret key K and the verification tag from a raw seed (raw_seed)
// # Arguments
// * `raw_seed` - vector of 4-bit nibbles forming the raw seed
// # Returns
// * tuple containing the secret key K (32 bytes) and the verification tag (32 bytes) used for authentication
fn derive_key_and_tag(raw_seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    // SHA-256 hasher deriving the key K from the raw seed
    let mut hasher_k = Sha256::new();
    // Hash the raw seed with a domain-separation prefix to avoid collisions
    hasher_k.update(b"HUMANVAULT_KEY_V1:");
    hasher_k.update(raw_seed);
    let k_digest = hasher_k.finalize();
    // Copy the SHA-256 digest into a fixed 32-byte array for the key K
    // Format expected by the rest of the code
    let mut key = [0u8; 32];
    key.copy_from_slice(&k_digest);

    // Same steps to derive the verification tag from the key K
    let mut hasher_tag = Sha256::new();
    hasher_tag.update(b"HUMANVAULT_TAG_V1:");
    hasher_tag.update(&key);
    let tag_digest = hasher_tag.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&tag_digest);

    (key, tag)
}

/// ENROLLMENT
/// # Arguments
/// * `face_master` - master biometric vector (at least 8 dimensions)
/// # Returns
/// * Enrollment result containing the secret key K and the helper data
pub fn fuzzy_enroll(face_master: &[f32]) -> Result<EnrollmentOutput, &'static str> {
    if face_master.len() < 8 {
        return Err("The biometric vector must have at least 8 dimensions");
    }

    // Generate the grid offsets for each dimension of the master biometric vector
    let grid_offsets = generate_grid_offsets(face_master);

    // Quantize the master biometric vector into Gray code using the offsets computed above
    let gray_master = quantize_to_gray(face_master, &grid_offsets);

    // Hash of the quantized Gray code (master_digest)
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(b"HUMANVAULT_MASTER_SEED:");
    seed_hasher.update(&gray_master);
    let master_digest = seed_hasher.finalize();

    // commitment_mask: used to correct errors during authentication
    let mut commitment_mask = Vec::with_capacity(gray_master.len());
    // canonical_seed: later used to derive the secret key K and the verification tag
    let mut canonical_seed = Vec::with_capacity(gray_master.len());

    // Build the commitment mask and the canonical seed from the Gray code and its digest
    for (i, &g_byte) in gray_master.iter().enumerate() {
        // nibble: 4 bits derived from the master digest, adding randomness to the canonical seed
        let nibble = (master_digest[i % 32] ^ (i as u8)) & 0x0F;
        canonical_seed.push(nibble);
        // codeword: Hamming (7,4) code of the nibble, for error correction
        let codeword = hamming74_encode_nibble(nibble);
        // commitment_mask: XOR between the codeword and the quantized Gray code (g_byte), for each dimension
        commitment_mask.push(codeword ^ g_byte);
    }

    // Derive the secret key K and the verification tag from the canonical seed
    let (secret_key, key_verification_tag) = derive_key_and_tag(&canonical_seed);
    // Zeroize the canonical seed to prevent any leak of sensitive data
    canonical_seed.zeroize();

    Ok(EnrollmentOutput {
        secret_key,
        helper_data: FuzzyHelperData {
            grid_offsets,
            commitment_mask,
            key_verification_tag,
        },
    })
}

/// AUTHENTICATION (reconstruction of the key K)
pub fn fuzzy_reconstruct(
    face_new: &[f32],
    helper: &FuzzyHelperData,
) -> Result<[u8; 32], &'static str> {
    if face_new.len() != helper.commitment_mask.len() || face_new.len() != helper.grid_offsets.len()
    {
        return Err("Vector dimension incompatible with the helper data");
    }

    let mut gray_new = quantize_to_gray(face_new, &helper.grid_offsets);
    let mut recovered_seed = Vec::with_capacity(face_new.len());

    for (i, &g_byte) in gray_new.iter().enumerate() {
        // Recover the noisy codeword by XORing the quantized Gray code with the commitment mask
        let noisy_codeword = helper.commitment_mask[i] ^ g_byte;
        // Error correction with Hamming (7,4) decoding to recover the original nibble
        let corrected_nibble = hamming74_decode_nibble(noisy_codeword);
        recovered_seed.push(corrected_nibble);
    }

    // Zeroize the quantized vector to prevent any leak of sensitive data
    gray_new.zeroize();
    // Recover the secret key K and the verification tag from the recovered seed
    let (mut candidate_key, candidate_tag) = derive_key_and_tag(&recovered_seed);
    // Zeroize the recovered seed to prevent any leak of sensitive data
    recovered_seed.zeroize();

    // Compare the computed verification tag with the one stored in the helper data to validate the reconstruction
    if bool::from(candidate_tag.ct_eq(&helper.key_verification_tag)) {
        Ok(candidate_key)
    } else {
        candidate_key.zeroize();
        Err("Biometric reconstruction failed: noise exceeds the correction capacity")
    }
}
#[cfg(test)]
mod tests {
    /// Constants for the Hamming (N, K) code
    /// N: total number of bits in the codeword (7 bits for Hamming (7,4))
    /// K: number of data bits (4 bits for a nibble)
    const N: u32 = 7;
    const K: u32 = 4;
    /// Tolerance used to compare reconstructed floats.
    /// Very small compared to half a cell (0.025): a rounding error cannot
    /// change the cell, but a genuine formula error would be detected.
    const FLOAT_TOLERANCE: f32 = 1e-5;
    // Number of iterations in the test loops
    const NUM_TEST: u32 = 1000;

    use super::*;
    use crate::utils::read_face_vector_from_json;
    use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

    /// Checks that for each cell index (idx),
    /// binary_to_gray(idx) differs from binary_to_gray(idx+1) by exactly one bit (i.e., the quantization is stable)
    #[test]
    fn test_gray_adjacent_indices_differ_by_one_bit() {
        for idx in 0u8..u8::MAX {
            let xor_gray_idx = binary_to_gray(idx) ^ binary_to_gray(idx + 1);
            assert_eq!(
                xor_gray_idx.count_ones(),
                1,
                "Unstable cell between {} (gray code = {:08b}) and {} (gray code = {:08b})",
                idx,
                binary_to_gray(idx),
                idx + 1,
                binary_to_gray(idx + 1)
            );
        }
    }

    /// Converts a Gray-coded integer back to a binary integer
    /// # Argument
    /// * `y` - Gray-coded integer (0-255)
    /// # Returns
    /// * corresponding binary integer (0-255)
    #[inline]
    fn gray_to_binary(y: u8) -> u8 {
        let mut n = y;
        let mut shift = 1;
        while shift < 8 {
            n ^= n >> shift;
            shift <<= 1;
        }
        n
    }

    /// Dequantizes a vector of Gray-coded bytes into floats, with a per-dimension offset
    /// # Arguments
    /// * `w` - vector of Gray-coded quantized bytes
    /// * `offsets` - per-dimension offsets bringing
    ///   the values back to the center of their quantization cell
    /// # Returns
    /// * vector of dequantized floats
    fn dequantize(w: &[u8], offsets: &[f32]) -> Vec<f32> {
        let mut out = Vec::with_capacity(w.len());
        for (i, &val_byte) in w.iter().enumerate() {
            // Number of the cell containing val_byte, after Gray -> binary conversion
            let idx = gray_to_binary(val_byte) as i32;
            // Center of the cell
            let cell_center = find_cell_center(idx);
            // Offset of dimension i
            let offset = offsets.get(i).copied().unwrap_or(0.0);
            // Actual value
            let val = cell_center + offset;
            out.push(val);
        }
        out
    }

    /// Checks that binary -> Gray -> binary is the identity for every cell index (0-255)
    #[test]
    fn test_gray_to_binary() {
        for idx in 0u8..=u8::MAX {
            assert_eq!(gray_to_binary(binary_to_gray(idx)), idx);
        }
    }

    /// Checks on the enrollment mock that:
    /// 1. dequantize then quantize gives back the same w (round trip on the bytes);
    /// 2. dequantize gives back the original face vector, within FLOAT_TOLERANCE
    ///    (since at enrollment, value = cell center + offset).
    #[test]
    fn test_quantize_dequantize_mock() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/mocks/Face_Mock_Enroll.json");
        let face_master = read_face_vector_from_json(path).unwrap();
        let offsets = generate_grid_offsets(&face_master);
        let w = quantize_to_gray(&face_master, &offsets);
        let reconstructed = dequantize(&w, &offsets);

        assert_eq!(
            quantize_to_gray(&reconstructed, &offsets),
            w,
            "The dequantize -> quantize round trip does not give back w"
        );

        for (i, (&original, &rebuilt)) in face_master.iter().zip(reconstructed.iter()).enumerate() {
            let gap = (original - rebuilt).abs();
            assert!(
                gap < FLOAT_TOLERANCE,
                "Dimension {i}: original = {original}, rebuilt = {rebuilt}, gap = {gap:e}"
            );
        }
    }

    /// Checks that quantization and dequantization are consistent for
    /// every byte value in every dimension of a master biometric vector
    /// (the dimensions being independent)
    #[test]
    fn test_quantize_dequantize_all() {
        let mut w = [0; 8];
        let offsets = generate_grid_offsets(
            &read_face_vector_from_json(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/mocks/Face_Mock_Enroll.json"
            ))
            .unwrap(),
        );
        for gray_byte in 0..=u8::MAX {
            for i in 0..w.len() {
                w[i] = gray_byte;
                assert_eq!(
                    quantize_to_gray(&dequantize(&w, &offsets), &offsets),
                    w,
                    "Dequantization error in dimension {i}, byte {gray_byte:08b}"
                );
            }
        }
    }

    /// Checks that decoding the encoding of a nibble (half byte) gives back the original nibble
    #[test]
    fn test_hamming74_encode_decode() {
        for nibble in 0u8..(1 << K) {
            assert_eq!(
                hamming74_decode_nibble(hamming74_encode_nibble(nibble)),
                nibble,
                "Round-trip error on {} ({:04b})",
                nibble,
                nibble
            );
        }
    }

    /// Checks the correction of a single-bit error
    #[test]
    fn test_hamming74_single_bit_noise_correction() {
        for nibble in 0u8..(1 << K) {
            let cw = hamming74_encode_nibble(nibble);
            for i in 0..N {
                let noisy_cw = cw ^ (1 << i);
                let nibble_corrected = hamming74_decode_nibble(noisy_cw);
                assert_eq!(
                    nibble_corrected, nibble,
                    "Failed to correct {} with bit {} of the Hamming codeword flipped: cw = {:07b}, noisy_cw = {:07b}",
                    nibble, i, cw, noisy_cw
                );
            }
        }
    }

    // Checks the correction of a single-bit error when bit 7 (outside the 7-bit codeword, ignored by the decoder) is also flipped
    #[test]
    fn test_hamming74_7th_bit_noise_and_single_bit_noise_correction() {
        for nibble in 0u8..(1 << K) {
            let cw = hamming74_encode_nibble(nibble);
            for i in 0..N {
                let noisy_cw = cw ^ (1 << i) ^ (1 << N);
                let nibble_corrected = hamming74_decode_nibble(noisy_cw);
                assert_eq!(
                    nibble_corrected, nibble,
                    "Failed to correct {} with bit {} and bit 7 of the codeword flipped: cw = {:07b}, noisy_cw = {:07b}",
                    nibble, i, cw, noisy_cw
                );
            }
        }
    }

    #[test]
    fn test_go_no_go_fuzzy_commitment() {
        // Master biometric vector from Face_Mock_Enroll.json
        let enroll_path = concat!(env!("CARGO_MANIFEST_DIR"), "/mocks/Face_Mock_Enroll.json");
        let face_master = read_face_vector_from_json(enroll_path).unwrap();

        // Noisy vector from Face_Mock_Auth.json (new capture)
        let auth_path = concat!(env!("CARGO_MANIFEST_DIR"), "/mocks/Face_Mock_Auth.json");
        let face_new = read_face_vector_from_json(auth_path).unwrap();

        // 1. ENROLLMENT: create the original key and the helper data
        let enrollment = fuzzy_enroll(&face_master).expect("Error: enrollment failed");
        let original_key = enrollment.secret_key;

        // 2. AUTHENTICATION: try to reconstruct the key from the noisy vector
        let reconstructed_key = fuzzy_reconstruct(&face_new, &enrollment.helper_data)
            .expect("Go/No-Go failed: the biometric noise could not be corrected");

        // 3. VERDICT: strict comparison of the 32 bytes
        assert_eq!(
            original_key, reconstructed_key,
            "NO-GO: the reconstructed key is not bit-for-bit identical to the original!"
        );
    }

    fn add_noise(w: &[u8], num_inv_bits: usize, rng: &mut StdRng) -> Vec<u8> {
        let total_bits = w.len() * 8;
        assert!(
            num_inv_bits < total_bits,
            "num_inv_bits too large: {num_inv_bits}"
        );
        let mut noisy_w = w.to_vec();

        // All bit positions
        let positions: Vec<usize> = (0..total_bits).collect();

        // choose_multiple: sampling without replacement
        for pos in positions.choose_multiple(rng, num_inv_bits as usize) {
            let byte_idx = *pos / 8;
            let bit_idx = (*pos % 8) as u8;
            noisy_w[byte_idx] ^= 1 << bit_idx;
        }

        noisy_w
    }

    #[test]
    fn test_fuzzy_commitment_k_inversed_bits() {
        // Master biometric vector from Face_Mock_Enroll.json
        let enroll_path = concat!(env!("CARGO_MANIFEST_DIR"), "/mocks/Face_Mock_Enroll.json");
        let face_master = read_face_vector_from_json(enroll_path).unwrap();
        // Enrollment
        let enrollment = fuzzy_enroll(&face_master).expect("Error: enrollment failed");
        // Retrieve the secret key
        let original_key = enrollment.secret_key;
        // Retrieve the offsets
        let grid_offsets = &enrollment.helper_data.grid_offsets;
        // Regenerate gray_master (already computed inside fuzzy_enroll())
        let gray_master = quantize_to_gray(&face_master, &grid_offsets);
        // RNG with a fixed seed
        let seed = 42;
        let mut rng = StdRng::seed_from_u64(seed);
        // Counters (success / failure)
        let mut num_pass;
        let mut num_clean_fail;
        let mut num_bad_fail;
        // Loop over the number k of flipped bits
        for num_inv_bits in 0..=8 {
            // Reset the counters
            num_pass = 0;
            num_clean_fail = 0;
            num_bad_fail = 0;
            // Inner loop over NUM_TEST samples
            for _ in 1..=NUM_TEST {
                // Flip k bits of gray_master to get gray_noisy
                let gray_noisy = add_noise(&gray_master, num_inv_bits, &mut rng);
                // Check that gray_noisy and gray_master differ by exactly k bits
                let num_diff_bits: u32 = gray_noisy
                    .iter()
                    .zip(gray_master.iter())
                    .map(|(byte_noisy, byte_master)| (byte_noisy ^ byte_master).count_ones())
                    .sum();
                assert_eq!(
                    num_diff_bits, num_inv_bits as u32,
                    "Inconsistent number of flipped bits"
                );

                // Rebuild face_noisy from gray_noisy (dequantization)
                let face_noisy = dequantize(&gray_noisy, &grid_offsets);
                // Authentication
                let authentification = fuzzy_reconstruct(&face_noisy, &enrollment.helper_data);

                match authentification {
                    Ok(reconstructed_key) => {
                        if reconstructed_key == original_key {
                            num_pass += 1;
                        } else {
                            num_bad_fail += 1;
                        }
                    }
                    Err(_) => {
                        num_clean_fail += 1;
                    }
                }
            }
            let num_total = num_clean_fail + num_pass + num_bad_fail;
            println!("================== Results for {num_inv_bits} flipped bits ({num_total} samples) ==================");
            println!("Successes: {num_pass}/{num_total}, clean failures: {num_clean_fail}/{num_total}, abnormal failures: {num_bad_fail}/{num_total}");
            let success_rate = (num_pass as f64 / num_total as f64) * 100.0;
            println!("Success rate: {:.2} %\n", success_rate);
            match num_inv_bits {
                0 | 1 => assert_eq!(
                    num_pass, num_total,
                    "100% success rate not reached for num_inv_bits = {num_inv_bits}"
                ),
                _ => assert_eq!(num_bad_fail, 0, "Abnormal failure detected"),
            }
        }
    }
}
