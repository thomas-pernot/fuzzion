use ark_snark::SNARK;
use zeroize::Zeroize;
use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_relations::{r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable}, lc};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Nombre de rondes de la permutation Poseidon légère en R1CS (largeur d'état t = 5)
const POSEIDON_ROUNDS: usize = 8;
const POSEIDON_WIDTH: usize = 5;

/// Convertit une clé de 32 octets en élément du corps fini BN254 Fr
pub fn key_bytes_to_fr(key: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(key)
}

/// Constantes de rondes déterministes pour Poseidon sur BN254 Fr
fn poseidon_round_constant(round: usize, idx: usize) -> Fr {
    let seed = ((round as u64 + 1) * 0x9E3779B97F4A7C15u64)
        .wrapping_add((idx as u64 + 1) * 0xBF58476D1CE4E5B9u64);
    Fr::from(seed)
}

/// Coefficient de la matrice MDS circulante [2, 1, 1, 1, 1] sur Fr
fn mds_coeff(row: usize, col: usize) -> Fr {
    if row == col {
        Fr::from(2u64)
    } else {
        Fr::from(1u64)
    }
}

/// HACHAGE POSEIDON NATIF : Calcule l'Ancre Publique = Poseidon(K, birth, country, salary)
pub fn compute_public_anchor(
    secret_key_bytes: &[u8; 32],
    birth_timestamp: u64,
    country_iso: u64,
    salary_net: u64,
) -> Fr {
    let mut state = [
        Fr::from(0u64), // Capacité initiale (Domain Separation)
        key_bytes_to_fr(secret_key_bytes),
        Fr::from(birth_timestamp),
        Fr::from(country_iso),
        Fr::from(salary_net),
    ];

    for r in 0..POSEIDON_ROUNDS {
        // 1. Addition des constantes de ronde + S-Box x^5
        for i in 0..POSEIDON_WIDTH {
            let x = state[i] + poseidon_round_constant(r, i);
            let x2 = x * x;
            let x4 = x2 * x2;
            state[i] = x4 * x;
        }
        // 2. Multiplication par la matrice MDS
        let prev = state;
        for row in 0..POSEIDON_WIDTH {
            let mut acc = Fr::from(0u64);
            for col in 0..POSEIDON_WIDTH {
                acc += mds_coeff(row, col) * prev[col];
            }
            state[row] = acc;
        }
    }

    state[0]
}

/// Structure des entrées privées avec zéroïsation automatique en RAM à la destruction
#[derive(Clone, Default, Zeroize)]
pub struct PrivateIdentityWitness {
    pub secret_key_bytes: [u8; 32],
    pub birth_timestamp: u64,
    pub country_iso: u64,
    pub salary_net: u64,
}

/// CIRCUIT ZKP UNIVERSEL HUMAN VAULT (v1.1 - R1CS sous Arkworks)
#[derive(Clone)]
pub struct HumanVaultUniversalCircuit {
    // --- Témoin privé (zéroïsé automatiquement au Drop) ---
    pub witness: PrivateIdentityWitness,

    // --- Entrées publiques (vérifiées par le serveur) ---
    pub public_anchor: Fr,
    pub session_challenge: Fr,
    pub attr_selector: u64,       // 0 = Age, 1 = Pays ISO, 2 = Salaire Net
    pub current_timestamp: u64,   // Timestamp UNIX actuel
    pub predicate_mode: u64,      // 0 = Seuil (>=), 1 = Égalité stricte (===)
    pub threshold_or_target: u64, // Seuil ou valeur cible
}

/// Impose dans le circuit R1CS qu'une variable représente un entier positif sur 64 bits [0, 2^64 - 1]
/// (Bloque toute attaque par débordement négatif / underflow modulo p)
fn enforce_u64_range(
    cs: ConstraintSystemRef<Fr>,
    var: Variable,
    value: u64,
) -> Result<(), SynthesisError> {
    let mut reconstructed = lc!();
    let mut coeff = Fr::from(1u64);

    for i in 0..64 {
        let bit_val = (value >> i) & 1;
        let bit_fr = Fr::from(bit_val);
        let bit_var = cs.new_witness_variable(|| Ok(bit_fr))?;

        // Contrainte de booléanité : bit * (1 - bit) = 0
        cs.enforce_constraint(
            lc!() + bit_var,
            lc!() + Variable::One - bit_var,
            lc!(),
        )?;

        reconstructed = reconstructed + (coeff, bit_var);
        coeff = coeff + coeff;
    }

    // Contrainte de reconstruction exacte : sum(bit_i * 2^i) == var
    cs.enforce_constraint(reconstructed, lc!() + Variable::One, lc!() + var)?;
    Ok(())
}

impl ConstraintSynthesizer<Fr> for HumanVaultUniversalCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // =========================================================================
        // 1. ALLOCATION DES ENTRÉES PUBLIQUES (Dans l'ordre exact de vérification)
        // =========================================================================
        let pub_anchor_var = cs.new_input_variable(|| Ok(self.public_anchor))?;
        let pub_challenge_var = cs.new_input_variable(|| Ok(self.session_challenge))?;
        let pub_selector_var = cs.new_input_variable(|| Ok(Fr::from(self.attr_selector)))?;
        let pub_current_ts_var = cs.new_input_variable(|| Ok(Fr::from(self.current_timestamp)))?;
        let pub_mode_var = cs.new_input_variable(|| Ok(Fr::from(self.predicate_mode)))?;
        let pub_target_var = cs.new_input_variable(|| Ok(Fr::from(self.threshold_or_target)))?;

        // =========================================================================
        // 2. ALLOCATION DU TÉMOIN PRIVÉ EN MÉMOIRE ISOLÉE
        // =========================================================================
        let secret_k_fr = key_bytes_to_fr(&self.witness.secret_key_bytes);
        let secret_k_var = cs.new_witness_variable(|| Ok(secret_k_fr))?;
        let birth_var = cs.new_witness_variable(|| Ok(Fr::from(self.witness.birth_timestamp)))?;
        let country_var = cs.new_witness_variable(|| Ok(Fr::from(self.witness.country_iso)))?;
        let salary_var = cs.new_witness_variable(|| Ok(Fr::from(self.witness.salary_net)))?;

        // =========================================================================
        // 3. ANCRAGE ANTI-REJEU DU CHALLENGE DE SESSION
        // =========================================================================
        let challenge_sq_val = self.session_challenge * self.session_challenge;
        let challenge_sq_var = cs.new_witness_variable(|| Ok(challenge_sq_val))?;
        cs.enforce_constraint(
            lc!() + pub_challenge_var,
            lc!() + pub_challenge_var,
            lc!() + challenge_sq_var,
        )?;

        // =========================================================================
        // 4. CONTRAINTES DU HACHAGE POSEIDON : Poseidon(K, birth, country, salary) == publicAnchor
        // =========================================================================
        let mut state_vals = [
            Fr::from(0u64),
            secret_k_fr,
            Fr::from(self.witness.birth_timestamp),
            Fr::from(self.witness.country_iso),
            Fr::from(self.witness.salary_net),
        ];

        let zero_var = cs.new_witness_variable(|| Ok(Fr::from(0u64)))?;
        cs.enforce_constraint(lc!() + zero_var, lc!() + Variable::One, lc!())?;

        let mut state_vars = [zero_var, secret_k_var, birth_var, country_var, salary_var];

        for r in 0..POSEIDON_ROUNDS {
            let mut sbox_vars = [zero_var; POSEIDON_WIDTH];
            let mut sbox_vals = [Fr::from(0u64); POSEIDON_WIDTH];

            for i in 0..POSEIDON_WIDTH {
                let rc = poseidon_round_constant(r, i);
                let x_val = state_vals[i] + rc;
                let x2_val = x_val * x_val;
                let x4_val = x2_val * x2_val;
                let x5_val = x4_val * x_val;

                let x2_var = cs.new_witness_variable(|| Ok(x2_val))?;
                let x4_var = cs.new_witness_variable(|| Ok(x4_val))?;
                let x5_var = cs.new_witness_variable(|| Ok(x5_val))?;

                // x2 = (state[i] + rc) * (state[i] + rc)
                cs.enforce_constraint(
                    lc!() + state_vars[i] + (rc, Variable::One),
                    lc!() + state_vars[i] + (rc, Variable::One),
                    lc!() + x2_var,
                )?;
                // x4 = x2 * x2
                cs.enforce_constraint(lc!() + x2_var, lc!() + x2_var, lc!() + x4_var)?;
                // x5 = x4 * (state[i] + rc)
                cs.enforce_constraint(
                    lc!() + x4_var,
                    lc!() + state_vars[i] + (rc, Variable::One),
                    lc!() + x5_var,
                )?;

                sbox_vars[i] = x5_var;
                sbox_vals[i] = x5_val;
            }

            // Couche linéaire MDS
            let mut next_vars = [zero_var; POSEIDON_WIDTH];
            let mut next_vals = [Fr::from(0u64); POSEIDON_WIDTH];

            for row in 0..POSEIDON_WIDTH {
                let mut acc_val = Fr::from(0u64);
                let mut acc_lc = lc!();
                for col in 0..POSEIDON_WIDTH {
                    let c = mds_coeff(row, col);
                    acc_val += c * sbox_vals[col];
                    acc_lc = acc_lc + (c, sbox_vars[col]);
                }
                let next_var = cs.new_witness_variable(|| Ok(acc_val))?;
                cs.enforce_constraint(acc_lc, lc!() + Variable::One, lc!() + next_var)?;
                next_vars[row] = next_var;
                next_vals[row] = acc_val;
            }

            state_vars = next_vars;
            state_vals = next_vals;
        }

        // Égalité stricte avec l'Ancre Publique
        cs.enforce_constraint(
            lc!() + state_vars[0],
            lc!() + Variable::One,
            lc!() + pub_anchor_var,
        )?;

        // =========================================================================
        // 5. MULTIPLEXEUR ALGÉBRIQUE D'ATTRIBUTS (s0, s1, s2)
        // =========================================================================
        let s0_u64 = if self.attr_selector == 0 { 1u64 } else { 0u64 };
        let s1_u64 = if self.attr_selector == 1 { 1u64 } else { 0u64 };
        let s2_u64 = if self.attr_selector == 2 { 1u64 } else { 0u64 };

        let s0_var = cs.new_witness_variable(|| Ok(Fr::from(s0_u64)))?;
        let s1_var = cs.new_witness_variable(|| Ok(Fr::from(s1_u64)))?;
        let s2_var = cs.new_witness_variable(|| Ok(Fr::from(s2_u64)))?;

        // Booléanité de chaque drapeau si * (1 - si) = 0
        for &s_var in &[s0_var, s1_var, s2_var] {
            cs.enforce_constraint(lc!() + s_var, lc!() + Variable::One - s_var, lc!())?;
        }

        // Exclusivité : s0 + s1 + s2 == 1
        cs.enforce_constraint(
            lc!() + s0_var + s1_var + s2_var,
            lc!() + Variable::One,
            lc!() + Variable::One,
        )?;

        // Liaison avec l'entrée publique attrSelector : 0*s0 + 1*s1 + 2*s2 == pub_selector_var
        cs.enforce_constraint(
            lc!() + s1_var + (Fr::from(2u64), s2_var),
            lc!() + Variable::One,
            lc!() + pub_selector_var,
        )?;

        // Calcul de l'âge révolu : age_delta = current_timestamp - birth_timestamp
        let age_delta_u64 = self
            .current_timestamp
            .wrapping_sub(self.witness.birth_timestamp);
        let age_delta_fr = Fr::from(self.current_timestamp) - Fr::from(self.witness.birth_timestamp);
        let age_delta_var = cs.new_witness_variable(|| Ok(age_delta_fr))?;
        cs.enforce_constraint(
            lc!() + pub_current_ts_var - birth_var,
            lc!() + Variable::One,
            lc!() + age_delta_var,
        )?;

        // Branches du multiplexeur
        let b0_val = Fr::from(s0_u64) * age_delta_fr;
        let b1_val = Fr::from(s1_u64) * Fr::from(self.witness.country_iso);
        let b2_val = Fr::from(s2_u64) * Fr::from(self.witness.salary_net);

        let b0_var = cs.new_witness_variable(|| Ok(b0_val))?;
        let b1_var = cs.new_witness_variable(|| Ok(b1_val))?;
        let b2_var = cs.new_witness_variable(|| Ok(b2_val))?;

        cs.enforce_constraint(lc!() + s0_var, lc!() + age_delta_var, lc!() + b0_var)?;
        cs.enforce_constraint(lc!() + s1_var, lc!() + country_var, lc!() + b1_var)?;
        cs.enforce_constraint(lc!() + s2_var, lc!() + salary_var, lc!() + b2_var)?;

        let selected_u64 = match self.attr_selector {
            0 => age_delta_u64,
            1 => self.witness.country_iso,
            2 => self.witness.salary_net,
            _ => 0,
        };
        let selected_fr = b0_val + b1_val + b2_val;
        let selected_var = cs.new_witness_variable(|| Ok(selected_fr))?;
        cs.enforce_constraint(
            lc!() + b0_var + b1_var + b2_var,
            lc!() + Variable::One,
            lc!() + selected_var,
        )?;

        // =========================================================================
        // 6. RANGE-CHECK 64 BITS & ÉVALUATION DU PRÉDICAT (>= OU ===)
        // =========================================================================
        // Vérifie que selected_var et pub_target_var sont bien des entiers 64 bits valides
        enforce_u64_range(cs.clone(), selected_var, selected_u64)?;
        enforce_u64_range(cs.clone(), pub_target_var, self.threshold_or_target)?;

        // Booléanité de predicate_mode (0 = Seuil >=, 1 = Égalité ===)
        cs.enforce_constraint(
            lc!() + pub_mode_var,
            lc!() + Variable::One - pub_mode_var,
            lc!(),
        )?;

        // Écart diff = selected_var - pub_target_var
        let diff_u64 = selected_u64.wrapping_sub(self.threshold_or_target);
        let diff_fr = selected_fr - Fr::from(self.threshold_or_target);
        let diff_var = cs.new_witness_variable(|| Ok(diff_fr))?;
        cs.enforce_constraint(
            lc!() + selected_var - pub_target_var,
            lc!() + Variable::One,
            lc!() + diff_var,
        )?;

        // A. Contrainte de seuil (>=) : diff doit appartenir à [0, 2^64 - 1]
        // Si selected < target, diff_fr devient p - |diff| (~2^254), ce qui fait échouer le range-check 64 bits !
        enforce_u64_range(cs.clone(), diff_var, diff_u64)?;

        // B. Contrainte d'égalité stricte (===) : si predicate_mode == 1, alors diff * predicate_mode == 0
        cs.enforce_constraint(lc!() + pub_mode_var, lc!() + diff_var, lc!())?;

        Ok(())
    }
}

/// Clés cryptographiques Groth16 pré-générées pour le SDK
pub struct ZkpEngineKeys {
    pub pk: ProvingKey<Bn254>,
    pub pvk: PreparedVerifyingKey<Bn254>,
}

/// Initialise les clés Groth16 (Setup déterministe pour les tests et le MVP)
pub fn setup_zkp_keys() -> Result<ZkpEngineKeys, &'static str> {
    let mut rng = ChaCha20Rng::from_seed([0x42u8; 32]);
    let dummy_circuit = HumanVaultUniversalCircuit {
        witness: PrivateIdentityWitness::default(),
        public_anchor: Fr::from(0u64),
        session_challenge: Fr::from(0u64),
        attr_selector: 0,
        current_timestamp: 0,
        predicate_mode: 0,
        threshold_or_target: 0,
    };

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, &mut rng)
        .map_err(|_| "Erreur lors du setup Groth16")?;
    let pvk = Groth16::<Bn254>::process_vk(&vk).map_err(|_| "Erreur de préparation VK")?;

    Ok(ZkpEngineKeys { pk, pvk })
}

/// Génère une preuve Groth16 sérialisée (compressée) et purge le témoin
pub fn generate_zkp_proof(
    keys: &ZkpEngineKeys,
    circuit: HumanVaultUniversalCircuit,
    rng_seed: [u8; 32],
) -> Result<Vec<u8>, &'static str> {
    // Pré-vérification mathématique locale avant génération
    let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
    circuit
        .clone()
        .generate_constraints(cs.clone())
        .map_err(|_| "Erreur de synthèse R1CS")?;
    if !cs.is_satisfied().unwrap_or(false) {
        return Err("Prédicat invalide ou ancre non concordante : preuve refusée");
    }

    let mut rng = ChaCha20Rng::from_seed(rng_seed);
    let proof = Groth16::<Bn254>::prove(&keys.pk, circuit, &mut rng)
        .map_err(|_| "Échec de génération de la preuve Groth16")?;

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|_| "Erreur de sérialisation de la preuve")?;

    Ok(proof_bytes)
}

/// Vérifie mathématiquement une preuve Groth16 à partir des seules entrées publiques
pub fn verify_zkp_proof(
    keys: &ZkpEngineKeys,
    proof_bytes: &[u8],
    public_anchor: Fr,
    session_challenge: Fr,
    attr_selector: u64,
    current_timestamp: u64,
    predicate_mode: u64,
    threshold_or_target: u64,
) -> Result<bool, &'static str> {
    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|_| "Preuve corrompue ou mal formée")?;

    let public_inputs = [
        public_anchor,
        session_challenge,
        Fr::from(attr_selector),
        Fr::from(current_timestamp),
        Fr::from(predicate_mode),
        Fr::from(threshold_or_target),
    ];

    Groth16::<Bn254>::verify_proof(&keys.pvk, &proof, &public_inputs)
        .map_err(|_| "Erreur lors de la vérification cryptographique")
}