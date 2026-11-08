
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use rand::RngExt;

use crate::utils::{FaceVector, read_face_vector_from_json};

// Convert a vector of floats to a binary vector using quantization
// Input : 
// - vector_face: vector of floats representing the face features
// Output :
// - quantized_vector_face : binary vector (result of quantization)
fn binary_quantization(vector_face: &FaceVector) -> Vec<u8> {
    let mut quantized_vector_face = Vec::with_capacity(vector_face.len());
    for x in vector_face {
        if *x > 0.0 {
            // Set corresponding bit to 1
            quantized_vector_face.push(1);
        } else {
            // Set corresponding bit to 0
            quantized_vector_face.push(0);
        }
    }
    quantized_vector_face
}

fn generate_random_key() -> Vec<u8> {
    let mut rng = rand::rng();
    let mut key = vec![0u8; 32]; // 256 bits
    rng.fill(&mut key[..]);
    key
}

// Commit a binary vector to a secret key using fuzzy commitment scheme
// Input : 
// - quantized_vector_face_master (result of quantization(vector_face_master))
// Output : 
// - k : 256 bit secret key (generated randomly ?)
// - hash : 256 bit hash of k
// - helper_data : additional data needed for fuzzy decommitment
fn fuzzy_commit(quantized_vector_face_master: &Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let k = generate_random_key();
    let hash = Sha256Gadget::digest(&k);
    unimplemented!()
}

// Decommit a binary vector to a secret key using fuzzy commitment scheme
// Input :
// - quantized_vector_face_slave (result of quantization(vector_face_slave))
// - hash (256 bit hash of the secret key)
// - helper_data (additional data needed for fuzzy decommitment)
// Output : 
// - k_prime : 256 bit key supposedly equal to k if quantized_vector_face_slave is close enough to quantized_vector_face_master
fn fuzzy_decommit(quantized_vector_face_slave: &Vec<u8>, hash: &Vec<u8>, helper_data: &Vec<u8>) -> Vec<u8> {
    unimplemented!()
}

#[test]
fn test_binary_quantization() {
    let vector_face = vec![0.5, -0.2, 0.0, 1.2, -0.7];
    let expected_quantized_vector_face = vec![1, 0, 0, 1, 0];
    let quantized_vector_face = binary_quantization(&vector_face);
    assert_eq!(quantized_vector_face, expected_quantized_vector_face);
}

#[test]
fn test_mock_binary_quantization() {
    let vector_face_enroll = read_face_vector_from_json("/home/kali/projects/humanvault-sdk/mocks/Face_Mock_Enroll.json").unwrap();
    let expected_vector_face = vec![1, 1, 0, 1, 0, 1, 1, 0];
    let quantized_vector_face = binary_quantization(&vector_face_enroll);
    assert_eq!(quantized_vector_face, expected_vector_face);
}