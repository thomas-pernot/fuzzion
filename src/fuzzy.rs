use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Données publiques d'aide (Helper Data) stockées ou transmises sans risque
/// # Champs
/// grid_offsets : offsets pour chaque dimension - ramène les valeurs au centre de la cellule de quantification
/// commitment_mask : masque de correction d'erreurs pour chaque dimension - utilisé pour corriger les erreurs lors de l'authentification
/// key_verification_tag : hash SHA256 de la clé secrète K pour vérification lors de l'authentification
#[derive(Clone, Debug, Zeroize)]
pub struct FuzzyHelperData {
    pub grid_offsets: Vec<f32>,
    pub commitment_mask: Vec<u8>,
    pub key_verification_tag: [u8; 32],
}

/// Résultat d'enrôlement contenant la clé secrète K (zéroïsée au Drop)
/// # Champs
/// secret_key : clé secrète K de 32 octets (zéroïsée au Drop)
/// helper_data : données publiques d'aide (Helper Data) pour l'authentification (non-zéroïsée)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EnrollmentOutput {
    pub secret_key: [u8; 32],
    #[zeroize(skip)]
    pub helper_data: FuzzyHelperData,
}

/// Constante de quantification pour le codage en code de Gray
/// Représente la largeur d'une case/cellule de quantification pour chaque dimension du vecteur biométrique
/// Chaque dimension est ramenée à un numéro de case/cellule
/// # Example
/// * QUANT_STEP = 0.05 veut dire que chaque dimension du vecteur biométrique est quantifiée par pas de 0.05
const QUANT_STEP: f32 = 0.05;

/// Constante représentant la taille d'une demi-cellule
const HALF_CELL: f32 = 0.5;

/// Constante représentant l'origine de la grille de quantification (borne inférieure de la case 0)
const GRID_ORIGIN: f32 = -2.0;

/// Conversion d'un entier binaire en code Gray
/// XOR entre le nombre et son décalage à droite de 1 bit
/// # Argument
/// * `n` - entier binaire (0-255)
/// # Retour
/// * entier Gray correspondant (0-255)
#[inline]
fn binary_to_gray(n: u8) -> u8 {
    n ^ (n >> 1)
}

/// Encodage Hamming (7,4) d'un nibble de 4 bits en codeword de 7 bits avec bits de parité pour correction d'erreurs
/// # Arguments
/// * `d` - nibble (demi-octet) de 4 bits (0-15)
/// # Retour
/// * codeword de 7 bits (0-127) avec bits de parité pour correction d'erreurs
/// # Exemple
/// * d = 0b1010 (10)
/// * d0 = 0, d1 = 1, d2 = 0, d3 = 1
/// * p0 = d0 ^ d1 ^ d3 = 0 ^ 1 ^ 1 = 0
/// * p1 = d0 ^ d2 ^ d3 = 0 ^ 0 ^ 1 = 1
/// * p2 = d1 ^ d2 ^ d3 = 1 ^ 0 ^ 1 = 0
/// * codeword = 0b0100101 (p0 p1 d0 p2 d1 d2 d3)
#[inline]
fn hamming74_encode_nibble(d: u8) -> u8 {
    // Extraction des bits de données d0, d1, d2, d3 du nibble d
    let d0 = (d >> 0) & 1;
    let d1 = (d >> 1) & 1;
    let d2 = (d >> 2) & 1;
    let d3 = (d >> 3) & 1;
    // Calcul des bits de parité p0, p1, p2 selon les formules de Hamming (7,4)
    let p0 = d0 ^ d1 ^ d3;
    let p1 = d0 ^ d2 ^ d3;
    let p2 = d1 ^ d2 ^ d3;
    // Assemblage du codeword de 7 bits (p0 p1 d0 p2 d1 d2 d3)
    (p0 << 0) | (p1 << 1) | (d0 << 2) | (p2 << 3) | (d1 << 4) | (d2 << 5) | (d3 << 6)
}

/// Décodage Hamming (7,4) d'un codeword de 7 bits en nibble de 4 bits avec correction d'erreurs
/// # Arguments
/// * `cw` - codeword de 7 bits (0-127) avec bits de parité pour correction d'erreurs
/// # Retour
/// * nibble de 4 bits (0-15) après correction d'erreurs
/// # Exemple
/// * cw = 0b0100101 (p0 p1 d0 p2 d1 d2 d3)
/// * b0 = 0, b1 = 1, b2 = 0, b3 = 0, b4 = 1, b5 = 0, b6 = 1
/// * s0 = b0 ^ b2 ^ b4 ^ b6 = 0 ^ 0 ^ 1 ^ 1 = 0
/// * s1 = b1 ^ b2 ^ b5 ^ b6 = 1 ^ 0 ^ 0 ^ 1 = 0
/// * s2 = b3 ^ b4 ^ b5 ^ b6 = 0 ^ 1 ^ 0 ^ 1 = 0
/// * syndrome = 0b000 = 0 (pas d'erreur)
/// * d0 = b2 = 0, d1 = b4 = 1, d2 = b5 = 0, d3 = b6 = 1
/// * nibble = 0b1010 (10)
#[inline]
fn hamming74_decode_nibble(mut cw: u8) -> u8 {
    // Extraction des bits du codeword de 7 bits (b0 à b6)
    let b0 = (cw >> 0) & 1;
    let b1 = (cw >> 1) & 1;
    let b2 = (cw >> 2) & 1;
    let b3 = (cw >> 3) & 1;
    let b4 = (cw >> 4) & 1;
    let b5 = (cw >> 5) & 1;
    let b6 = (cw >> 6) & 1;
    // Calcul du syndrome pour détecter et corriger une erreur unique
    let s0 = b0 ^ b2 ^ b4 ^ b6;
    let s1 = b1 ^ b2 ^ b5 ^ b6;
    let s2 = b3 ^ b4 ^ b5 ^ b6;
    let syndrome = s0 | (s1 << 1) | (s2 << 2);
    // Correction d'une erreur unique si le syndrome est non nul (1 à 7)
    if syndrome > 0 && syndrome <= 7 {
        cw ^= 1 << (syndrome - 1);
    }
    // Récupération des bits de données d0, d1, d2, d3 après correction
    let d0 = (cw >> 2) & 1;
    let d1 = (cw >> 4) & 1;
    let d2 = (cw >> 5) & 1;
    let d3 = (cw >> 6) & 1;
    // Reconstruction du nibble de 4 bits à partir des bits de données corrigés
    d0 | (d1 << 1) | (d2 << 2) | (d3 << 3)
}

/// Fonction auxiliaire pour trouver le centre d'une cellule
/// # Arguments
/// * idx : numéro de la cellule
/// # Retour
/// * Centre de la cellule
fn find_cell_center(idx: i32) -> f32 {
    (idx as f32 + HALF_CELL) * QUANT_STEP + GRID_ORIGIN
}

/// Génère les offsets pour ramener les valeurs au centre des cellules
/// # Arguments
/// * face_master : vecteur de flottants (données biométriques)
/// # Retour
/// * Vecteur des offsets par dimension
fn generate_grid_offsets(face_master: &[f32]) -> Vec<f32> {
    let mut grid_offsets = Vec::with_capacity(face_master.len());
    for &val in face_master.iter() {
        // base_idx : numéro de cellule contenant val
        let base_idx = ((val - GRID_ORIGIN) / QUANT_STEP) as i32;
        // cell_center : centre de la cellule contenant val (numéro de cellule = base_idx)
        let cell_center = find_cell_center(base_idx);
        // val - cell_center : offset pour ramener val au centre de la cellule de quantification
        grid_offsets.push(val - cell_center);
    }
    grid_offsets
}

/// Quantification d'un vecteur de flottants en code de Gray avec décalage (offset) pour chaque dimension
/// # Arguments
/// * `vector` - vecteur de flottants à quantifier
/// * `offsets` - vecteur de décalages pour chaque dimension pour ramener les valeurs au centre de la plage de quantification
/// # Retour
/// * vecteur de bytes quantifiés en code de Gray   
fn quantize_to_gray(vector: &[f32], offsets: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(vector.len());
    // val : valeur flottante de la dimension i du vecteur biométrique
    for (i, &val) in vector.iter().enumerate() {
        // Détermination du décalage (off) pour la dimension i, ou 0.0 si non fourni
        let off = offsets.get(i).copied().unwrap_or(0.0);
        // Décalage (retour au centre de la cellule)
        // val - off : valeur centrée sur la cellule de quantification
        // - GRID_ORIGIN : translation basée sur l'hypothèse que les valeurs seront toujours > GRID_ORIGIN
        // / QUANT_STEP : quantification en pas de QUANT_STEP pour obtenir un index
        // shifted : valeur flottante quantifiée avant conversion en entier
        let shifted = (val - off - GRID_ORIGIN) / QUANT_STEP;
        // Quantification en entier u8 (de 0 à 255) avant la conversion en code de Gray
        // idx : index/numéro de case quantifié en entier u8 (0-255) pour la dimension i
        let idx = if shifted < 0.0 {
            0u8
        } else if shifted > 255.0 {
            255u8
        } else {
            shifted as u8
        };
        // Ajout au vecteur de sortie du code de Gray correspondant à l'index quantifié
        out.push(binary_to_gray(idx));
    }
    out
}

// Dérivation de la clé secrète K et du tag de vérification à partir d'une graine brute (raw_seed)
// # Arguments
// * `raw_seed` - vecteur de nibbles (4 bits) représentant la graine brute
// # Retour
// * tuple contenant la clé secrète K (32 octets) et le tag de vérification (32 octets) pour authentification
fn derive_key_and_tag(raw_seed: &[u8]) -> ([u8; 32], [u8; 32]) {
    // Création d'un hasher SHA256 pour dériver la clé K à partir de la graine brute
    let mut hasher_k = Sha256::new();
    // Hash de la graine brute avec un préfixe pour éviter les collisions
    hasher_k.update(b"HUMANVAULT_KEY_V1:");
    hasher_k.update(raw_seed);
    let k_digest = hasher_k.finalize();
    // Copie du digest SHA256 dans un tableau fixe de 32 octets pour la clé K
    // Format attendu par le reste du code
    let mut key = [0u8; 32];
    key.copy_from_slice(&k_digest);

    // Actions similaires pour dériver le tag de vérification à partir de la clé K
    let mut hasher_tag = Sha256::new();
    hasher_tag.update(b"HUMANVAULT_TAG_V1:");
    hasher_tag.update(&key);
    let tag_digest = hasher_tag.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&tag_digest);

    (key, tag)
}

/// ENRÔLEMENT
/// # Arguments
/// * `face_master` - vecteur biométrique maître (8 dimensions minimum)
/// # Retour
/// * Résultat d'enrôlement contenant la clé secrète K et le Helper Data
pub fn fuzzy_enroll(face_master: &[f32]) -> Result<EnrollmentOutput, &'static str> {
    if face_master.len() < 8 {
        return Err("Le vecteur biométrique doit comporter au moins 8 dimensions");
    }

    // Génération des offsets de grille pour chaque dimension du vecteur biométrique maître
    let grid_offsets = generate_grid_offsets(face_master);

    // Quantification du vecteur biométrique maître en code de Gray avec les offsets calculés précédemment
    let gray_master = quantize_to_gray(face_master, &grid_offsets);

    // Hash du code Gray quantifié (master_digest)
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(b"HUMANVAULT_MASTER_SEED:");
    seed_hasher.update(&gray_master);
    let master_digest = seed_hasher.finalize();

    // commitment_mask : utilisé pour corriger les erreurs lors de l'authentification
    let mut commitment_mask = Vec::with_capacity(gray_master.len());
    // canonical_seed : utilisé plus tard pour dériver la clé secrète K et le tag de vérification
    let mut canonical_seed = Vec::with_capacity(gray_master.len());

    // Génération du commitment mask et de la canonical seed à partir du code Gray et de son digest
    for (i, &g_byte) in gray_master.iter().enumerate() {
        // nibble : 4 bits dérivés du digest maître pour introduire de l'aléatoire dans la graine canonique
        let nibble = (master_digest[i % 32] ^ (i as u8)) & 0x0F;
        canonical_seed.push(nibble);
        // codeword : code de Hamming (7,4) du nibble pour correction d'erreurs
        let codeword = hamming74_encode_nibble(nibble);
        // commitment_mask : concaténation des XOR entre le codeword et le code Gray quantifié (g_byte) pour chaque dimension
        commitment_mask.push(codeword ^ g_byte);
    }

    // Dérivation de la clé secrète K et du tag de vérification à partir de la graine canonique
    let (secret_key, key_verification_tag) = derive_key_and_tag(&canonical_seed);
    // Zéroïsation de la graine canonique pour éviter toute fuite de données sensibles
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
    if face_new.len() != helper.commitment_mask.len() || face_new.len() != helper.grid_offsets.len()
    {
        return Err("Dimension du vecteur incompatible avec le Helper Data");
    }

    let mut gray_new = quantize_to_gray(face_new, &helper.grid_offsets);
    let mut recovered_seed = Vec::with_capacity(face_new.len());

    for (i, &g_byte) in gray_new.iter().enumerate() {
        // Récupération du codeword bruité en XORant le code Gray quantifié avec le commitment mask
        let noisy_codeword = helper.commitment_mask[i] ^ g_byte;
        // Correction d'erreurs avec le décodage Hamming (7,4) pour récupérer le nibble original
        let corrected_nibble = hamming74_decode_nibble(noisy_codeword);
        recovered_seed.push(corrected_nibble);
    }

    // Zéroïsation du vecteur quantifié pour éviter toute fuite de données sensibles
    gray_new.zeroize();
    // Récupération de la clé secrète K et du tag de vérification à partir de la graine récupérée
    let (mut candidate_key, candidate_tag) = derive_key_and_tag(&recovered_seed);
    // Zéroïsation de la graine récupérée pour éviter toute fuite de données sensibles
    recovered_seed.zeroize();

    // Comparaison du tag de vérification calculé avec celui stocké dans le Helper Data pour valider la reconstruction
    if bool::from(candidate_tag.ct_eq(&helper.key_verification_tag)) {
        Ok(candidate_key)
    } else {
        candidate_key.zeroize();
        Err("Échec de reconstruction biométrique : bruit supérieur à la capacité de correction")
    }
}
#[cfg(test)]
mod tests {
    /// Constantes pour le codage Hamming (N, K)
    /// N : nombre total de bits du codeword (7 bits pour Hamming (7,4))
    /// K : nombre de bits de données (4 bits pour un nibble)
    const N: u32 = 7;
    const K: u32 = 4;
    /// Tolérance pour comparer des flottants reconstruits.
    /// Très petite devant une demi-case (0,025) : une erreur d'arrondi ne peut pas
    /// faire changer de case, mais une vraie erreur de formule serait détectée.
    const FLOAT_TOLERANCE: f32 = 1e-5;
    // Nombre d'itération dans les boucles de test
    const NUM_TEST: u32 = 1000;
    
    use super::*;
    use crate::utils::read_face_vector_from_json;
    use rand::{rngs::StdRng, SeedableRng, seq::SliceRandom};

    /// Vérifie que pour chaque indice de cellule (idx)
    /// binary_gray(idx) diffère de binary_gray(idx+1) exactement d'un bit (i.e., la quantification est stable)
    #[test]
    fn test_gray_adjacent_indices_differ_by_one_bit() {
        for idx in 0u8..u8::MAX {
            let xor_gray_idx = binary_to_gray(idx) ^ binary_to_gray(idx + 1);
            assert_eq!(
                xor_gray_idx.count_ones(),
                1,
                "Cellule instable entre {} (gray code = {:08b}) et {} (gray code = {:08b})",
                idx,
                binary_to_gray(idx),
                idx + 1,
                binary_to_gray(idx + 1)
            );
        }
    }

    /// Conversion d'un entier en code Gray en entier binaire
    /// # Argument
    /// * `y` - entier Gray (0-255)
    /// # Retour
    /// * entier binaire correspondant (0-255)
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

    /// Déquantification d'un vecteur de bytes en code de Gray en flottants avec décalage (offset) pour chaque dimension
    /// # Arguments
    /// * `w` - vecteur de bytes quantifiés en code de Gray
    /// * `offsets` - vecteur de décalages pour chaque dimension pour ramener
    /// les valeurs au centre de la plage de quantification
    /// # Retour
    /// * vecteur de flottants déquantifiés
    fn dequantize(w: &[u8], offsets: &[f32]) -> Vec<f32> {
        let mut out = Vec::with_capacity(w.len());
        for (i, &val_byte) in w.iter().enumerate() {
            // Numéro de cellule contenant val_byte après conversion Gray -> Binaire
            let idx = gray_to_binary(val_byte) as i32;
            // Centre de la cellule
            let cell_center = find_cell_center(idx);
            // Récupération de l'offset
            let offset = offsets.get(i).copied().unwrap_or(0.0);
            // Valeur réelle
            let val = cell_center + offset;
            out.push(val);
        }
        out
    }

    /// Vérifie que la conversion binaire -> Gray -> binaire est bien l'identité pour tous les indices de cellule (0-255)
    #[test]
    fn test_gray_to_binary() {
        for idx in 0u8..=u8::MAX {
            assert_eq!(gray_to_binary(binary_to_gray(idx)), idx);
        }
    }

    /// Vérifie sur le mock d'enrôlement que :
    /// 1. dequantize puis quantize redonne le même w (aller-retour sur les octets) ;
    /// 2. dequantize redonne le vecteur facial d'origine, à FLOAT_TOLERANCE près
    ///    (car à l'enrôlement, valeur = centre de case + offset).
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
            "L'aller-retour dequantize -> quantize ne redonne pas w"
        );

        for (i, (&original, &rebuilt)) in face_master.iter().zip(reconstructed.iter()).enumerate() {
            let gap = (original - rebuilt).abs();
            assert!(
                gap < FLOAT_TOLERANCE,
                "Dimension {i} : original = {original}, reconstruit = {rebuilt}, écart = {gap:e}"
            );
        }
    }

    /// Vérifie que la quantification et la déquantification sur 
    /// chaque valeur d’octet dans chaque dimension d'un vecteur biométrique maître sont cohérentes
    /// (les dimensions étant indépendantes)
    #[test]
    fn test_quantize_dequantize_all(){
        let mut w = [0; 8];
        let offsets = generate_grid_offsets(&read_face_vector_from_json(concat!(env!("CARGO_MANIFEST_DIR"), "/mocks/Face_Mock_Enroll.json")).unwrap());
        for gray_byte in 0..=u8::MAX{
            for i in 0..w.len(){
                w[i] = gray_byte;
                assert_eq!(quantize_to_gray(&dequantize(&w, &offsets), &offsets), w, "Erreur dans la déquantification au test {i}, octet {gray_byte:08b}");
            }
        }
    }

    /// Vérifie que le décodage de l'encodage d'un nibble (demi-octet) est bien égal au nibble original
    #[test]
    fn test_hamming74_encode_decode() {
        for nibble in 0u8..(1 << K) {
            assert_eq!(
                hamming74_decode_nibble(hamming74_encode_nibble(nibble)),
                nibble,
                "Erreur lors de l'aller-retour sur {} ({:04b})",
                nibble,
                nibble
            );
        }
    }

    /// Vérification de correction d'erreur sur un unique bit
    #[test]
    fn test_hamming74_single_bit_noise_correction() {
        for nibble in 0u8..(1 << K) {
            let cw = hamming74_encode_nibble(nibble);
            for i in 0..N {
                let noisy_cw = cw ^ (1 << i);
                let nibble_corrected = hamming74_decode_nibble(noisy_cw);
                assert_eq!(
                    nibble_corrected, nibble,
                    "Erreur sur la correction de {} avec modification du hamming code au bit {} : cw = {:07b}, noisy_cw = {:07b}",
                    nibble, i, cw, noisy_cw
                );
            }
        }
    }

    // Vérification de correction d'erreur sur un unique bit avec le 7ème bit (bit de parité) modifié
    #[test]
    fn test_hamming74_7th_bit_noise_and_single_bit_noise_correction() {
        for nibble in 0u8..(1 << K) {
            let cw = hamming74_encode_nibble(nibble);
            for i in 0..N {
                let noisy_cw = cw ^ (1 << i) ^ (1 << N);
                let nibble_corrected = hamming74_decode_nibble(noisy_cw);
                assert_eq!(
                    nibble_corrected, nibble,
                    "Erreur sur la correction de {} avec modification du codeword au bit {} et bit 7: cw = {:07b}, noisy_cw = {:07b}",
                    nibble, i, cw, noisy_cw
                );
            }
        }
    }

    #[test]
    fn test_go_no_go_fuzzy_commitment() {
        // Vecteur biométrique maître issu de Face_Mock_Enroll.json
        let enroll_path = concat!(env!("CARGO_MANIFEST_DIR"), "/mocks/Face_Mock_Enroll.json");
        let face_master = read_face_vector_from_json(enroll_path).unwrap();

        // Vecteur bruité issu de Face_Mock_Auth.json (Nouvelle capture)
        let auth_path = concat!(env!("CARGO_MANIFEST_DIR"), "/mocks/Face_Mock_Auth.json");
        let face_new = read_face_vector_from_json(auth_path).unwrap();

        // 1. ENRÔLEMENT : Création de la clé originelle et du Helper Data
        let enrollment = fuzzy_enroll(&face_master).expect("Erreur : l'enrôlement a échoué");
        let original_key = enrollment.secret_key;

        // 2. AUTHENTIFICATION : Tentative de reconstruction de la clé avec le vecteur bruité
        let reconstructed_key = fuzzy_reconstruct(&face_new, &enrollment.helper_data)
            .expect("Échec du Go/No-Go : Le bruit biométrique n'a pas pu être corrigé");

        // 3. VERDICT : Comparaison stricte des 32 octets
        assert_eq!(
            original_key, reconstructed_key,
            "NO-GO : La clé reconstruite n'est pas identique à l'originale au bit près !"
        );
    }

    fn add_noise(w: &[u8], num_inv_bits: u8, rng : &mut StdRng) -> Vec<u8> {
        let total_bits = w.len() as u8 * 8;
        assert!(num_inv_bits<total_bits, "num_inv_bits trop grand : {num_inv_bits}");
        let mut noisy_w = w.to_vec();
        let total_bits = noisy_w.len() * 8;

        // Slice de toutes les positions de bits
        let positions: Vec<usize> = (0..total_bits).collect();

        // choose_multiple: échantillonnage sans répétition
        for pos in positions.choose_multiple(rng, num_inv_bits as usize) {
            let byte_idx = *pos / 8;
            let bit_idx  = (*pos % 8) as u8;
            noisy_w[byte_idx] ^= 1 << bit_idx;
        }

        noisy_w
    }   

    #[test]
    fn test_fuzzy_commitment_k_inversed_bits(){
        // Vecteur biométrique maître issu de Face_Mock_Enroll.json
        let enroll_path = concat!(env!("CARGO_MANIFEST_DIR"), "/mocks/Face_Mock_Enroll.json");
        let face_master = read_face_vector_from_json(enroll_path).unwrap();
        // Enrollement
        let enrollment = fuzzy_enroll(&face_master).expect("Erreur : l'enrôlement a échoué");
        // Récupération de la clé secrète 
        let original_key = enrollment.secret_key;
        // Récupération des offsets
        let grid_offsets = &enrollment.helper_data.grid_offsets;
        // (Re)génération de gray_master (déjà créé dans fuzzy_enroll())
        let gray_master = quantize_to_gray(&face_master, &grid_offsets);
        // Formatage pour les println! plus tard
        // let gray_master_bin: String = gray_master
        //     .iter()
        //     .map(|byte| format!("{:08b}", byte))
        //     .collect::<Vec<String>>()
        //     .join(" ");
        // Génération d'un RNG à partir d'une graine fixe
        let seed= 42;
        let mut rng = StdRng::seed_from_u64(seed);
        // Déclaration des compteurs (réussite/échec)
        let mut num_pass;
        let mut num_clean_fail;
        let mut num_bad_fail;
        // Boucle sur le nombre k de bits inversés
        for num_inv_bits in 0..=8{
            // Initialisation des compteurs
            num_pass = 0;
            num_clean_fail = 0;
            num_bad_fail = 0;
            // Boucle interne de 1000 échantillons
            for _ in 1..=NUM_TEST{
                // Modification de gray_noisy sur k positions (k bits inversés)
                let gray_noisy = add_noise(&gray_master, num_inv_bits, &mut rng);
                // Check qu'on a bien k bits différents entre gray_noisy et gray_master
                let num_diff_bits : u32 = gray_noisy
                    .iter()
                    .zip(gray_master.iter())
                    .map(|(byte_noisy, byte_master)| (byte_noisy ^ byte_master).count_ones())
                    .sum();
                assert_eq!(
                    num_diff_bits,
                    num_inv_bits as u32,
                    "Le nombre de bits inversés n'est pas cohérent"
                );
                
                //Reconstruction de face_noisy (à partir de gray_noisy, déquantification)
                let face_noisy = dequantize(&gray_noisy, &grid_offsets);
                // Authentification
                let authentification = fuzzy_reconstruct(&face_noisy, &enrollment.helper_data);

                //println!("\n------------- Tests sur {num_inv_bits} bits modifiés -------------\n");
                match authentification{
                    Ok(reconstructed_key) => {
                        if reconstructed_key == original_key{
                            num_pass += 1;
                            //println!("Clé reconstruite au bit près")
                        }
                        else {
                            num_bad_fail += 1;
                            // Formatage pour l'affichage
                            // let gray_noisy_bin: String = gray_noisy
                            //     .iter()
                            //     .map(|byte| format!("{:08b}", byte))
                            //     .collect::<Vec<String>>()
                            //     .join(" ");
                            // println!("Erreur : La clé reconstruite diffère de la clé originale \n
                            //     gray_master : {gray_master_bin} \n
                            //     gray_noisy : {gray_noisy_bin} \n
                            // ")
                        }
                    },
                    Err(_) => {
                        num_clean_fail += 1;
                        //println!("Erreur : la clé n'a pas pu être reconstruite");
                    }
                }
            }
            let num_total = num_clean_fail + num_pass + num_bad_fail;
            println!("================== Résultats pour une modification de {num_inv_bits} bits ({num_total} échantillons) ==================");
            println!("Réussites : {num_pass}/{num_total}, Echecs clean : {num_clean_fail}/{num_total}, Echecs anormaux : {num_bad_fail}/{num_total}");
            let success_rate = (num_pass as f64 / num_total as f64) * 100.0;
            println!("Pourcentage de réussite : {:.2} %\n", success_rate);
            match num_inv_bits {
                0 | 1 => assert_eq!(num_pass, num_total, "Taux de 100% de réussite non-atteint pour num_inv_bits = {num_inv_bits}"),
                _ => assert_eq!(num_bad_fail, 0, "Echec anormal détecté")
            }
        }
        

    }
}
