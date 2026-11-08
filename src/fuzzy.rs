use subtle::ConstantTimeEq;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Données publiques d'aide (Helper Data) stockées ou transmises sans risque
#[derive(Clone, Debug, Zeroize)]
pub struct FuzzyHelperData {
    pub grid_offsets: Vec<f32>,
    pub commitment_mask: Vec<u8>,
    pub key_verification_tag: [u8; 32],
}

/// Résultat d'enrôlement contenant la clé secrète K (zéroïsée au Drop)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EnrollmentOutput {
    pub secret_key: [u8; 32],
    #[zeroize(skip)]
    pub helper_data: FuzzyHelperData,
}

const QUANT_STEP: f32 = 0.05;

#[inline]
fn binary_to_gray(n: u8) -> u8 {
    n ^ (n >> 1)
}

#[inline]
fn hamming74_encode_nibble(d: u8) -> u8 {
    let d0 = (d >> 0) & 1;
    let d1 = (d >> 1) & 1;
    let d2 = (d >> 2) & 1;
    let d3 = (d >> 3) & 1;
    let p0 = d0 ^ d1 ^ d3;
    let p1 = d0 ^ d2 ^ d3;
    let p2 = d1 ^ d2 ^ d3;
    (p0 << 0) | (p1 << 1) | (d0 << 2) | (p2 << 3) | (d1 << 4) | (d2 << 5) | (d3 << 6)
}

#[inline]
fn hamming74_decode_nibble(mut cw: u8) -> u8 {
    let b0 = (cw >> 0) & 1;
    let b1 = (cw >> 1) & 1;
    let b2 = (cw >> 2) & 1;
    let b3 = (cw >> 3) & 1;
    let b4 = (cw >> 4) & 1;
    let b5 = (cw >> 5) & 1;
    let b6 = (cw >> 6) & 1;
    
    let s0 = b0 ^ b2 ^ b4 ^ b6;
    let s1 = b1 ^ b2 ^ b5 ^ b6;
    let s2 = b3 ^ b4 ^ b5 ^ b6;
    let syndrome = s0 | (s1 << 1) | (s2 << 2);
    
    if syndrome > 0 && syndrome <= 7 {
        cw ^= 1 << (syndrome - 1);
    }
    
    let d0 = (cw >> 2) & 1;
    let d1 = (cw >> 4) & 1;
    let d2 = (cw >> 5) & 1;
    let d3 = (cw >> 6) & 1;
    d0 | (d1 << 1) | (d2 << 2) | (d3 << 3)
}

fn quantize_to_gray(vector: &[f32], offsets: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(vector.len());
    for (i, &val) in vector.iter().enumerate() {
        let off = offsets.get(i).copied().unwrap_or(0.0);
        let shifted = (val - off + 2.0) / QUANT_STEP;
        let idx = if shifted < 0.0 {
            0u8
        } else if shifted > 255.0 {
            255u8
        } else {
            shifted as u8
        };
        out.push(binary_to_gray(idx));
    }
    out
}

fn derive_key_and_tag(raw_seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hasher_k = Sha256::new();
    hasher_k.update(b"HUMANVAULT_KEY_V1:");
    hasher_k.update(raw_seed);
    let k_digest = hasher_k.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&k_digest);
    
    let mut hasher_tag = Sha256::new();
    hasher_tag.update(b"HUMANVAULT_TAG_V1:");
    hasher_tag.update(&key);
    let tag_digest = hasher_tag.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&tag_digest);
    
    (key, tag)
}

/// ENRÔLEMENT
pub fn fuzzy_enroll(face_master: &[f32]) -> Result<EnrollmentOutput, &'static str> {
    if face_master.len() < 8 {
        return Err("Le vecteur biométrique doit comporter au moins 8 dimensions");
    }
    
    let mut grid_offsets = Vec::with_capacity(face_master.len());
    for &val in face_master.iter() {
        let base_idx = ((val + 2.0) / QUANT_STEP) as i32;
        let cell_center = (base_idx as f32 + 0.5) * QUANT_STEP - 2.0;
        grid_offsets.push(val - cell_center);
    }
    
    let gray_master = quantize_to_gray(face_master, &grid_offsets);
    
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(b"HUMANVAULT_MASTER_SEED:");
    seed_hasher.update(&gray_master);
    let master_digest = seed_hasher.finalize();
    
    let mut commitment_mask = Vec::with_capacity(gray_master.len());
    let mut canonical_seed = Vec::with_capacity(gray_master.len());
    
    for (i, &g_byte) in gray_master.iter().enumerate() {
        let nibble = (master_digest[i % 32] ^ (i as u8)) & 0x0F;
        canonical_seed.push(nibble);
        let codeword = hamming74_encode_nibble(nibble);
        commitment_mask.push(codeword ^ g_byte);
    }
    
    let (secret_key, key_verification_tag) = derive_key_and_tag(&canonical_seed);
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

/// AUTHENTIFICATION (Reconstruction de la clé K)
pub fn fuzzy_reconstruct(
    face_new: &[f32],
    helper: &FuzzyHelperData,
) -> Result<[u8; 32], &'static str> {
    if face_new.len() != helper.commitment_mask.len()
        || face_new.len() != helper.grid_offsets.len()
    {
        return Err("Dimension du vecteur incompatible avec le Helper Data");
    }
    
    let mut gray_new = quantize_to_gray(face_new, &helper.grid_offsets);
    let mut recovered_seed = Vec::with_capacity(face_new.len());
    
    for (i, &g_byte) in gray_new.iter().enumerate() {
        let noisy_codeword = helper.commitment_mask[i] ^ g_byte;
        let corrected_nibble = hamming74_decode_nibble(noisy_codeword);
        recovered_seed.push(corrected_nibble);
    }
    
    gray_new.zeroize();
    let (mut candidate_key, candidate_tag) = derive_key_and_tag(&recovered_seed);
    recovered_seed.zeroize();
    
    if bool::from(candidate_tag.ct_eq(&helper.key_verification_tag)) {
        Ok(candidate_key)
    } else {
        candidate_key.zeroize();
        Err("Échec de reconstruction biométrique : bruit supérieur à la capacité de correction")
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_no_go_fuzzy_commitment() {
        // Vecteur biométrique maître issu de Face_Mock_Enroll.json
        let face_master = [
            0.4512, 0.8954, -0.1245, 0.6721, -0.3318, 0.2190, 0.5541, -0.7845
        ];
        
        // Vecteur bruité issu de Face_Mock_Auth.json (Nouvelle capture)
        let face_new = [
            0.4515, 0.8951, -0.1240, 0.6718, -0.3321, 0.2194, 0.5538, -0.7841
        ];

        // 1. ENRÔLEMENT : Création de la clé originelle et du Helper Data
        let enrollment = fuzzy_enroll(&face_master)
            .expect("Erreur : l'enrôlement a échoué");
        let original_key = enrollment.secret_key;
        
        // 2. AUTHENTIFICATION : Tentative de reconstruction de la clé avec le vecteur bruité
        let reconstructed_key = fuzzy_reconstruct(&face_new, &enrollment.helper_data)
            .expect("Échec du Go/No-Go : Le bruit biométrique n'a pas pu être corrigé");

        // 3. VERDICT : Comparaison stricte des 32 octets
        assert_eq!(
            original_key, 
            reconstructed_key, 
            "NO-GO : La clé reconstruite n'est pas identique à l'originale au bit près !"
        );
    }
}