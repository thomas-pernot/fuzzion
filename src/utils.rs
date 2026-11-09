use serde::Deserialize;
use std::{collections::HashMap, error::Error, fs};

pub type FaceVector = Vec<f32>;
pub type NfcAttributesVector = HashMap<String, i128>;

#[derive(Deserialize)]  
struct FaceVectorFile {
    face_vector: FaceVector,
}

#[derive(Deserialize)]
struct NfcAttributesFile {
    nfc_attributes_vector: NfcAttributesVector,
}

pub fn read_face_vector_from_json(file_path: &str) -> Result<FaceVector, Box<dyn Error>> {
    let json_content = fs::read_to_string(file_path)?;
    let file: FaceVectorFile = serde_json::from_str(&json_content)?;
    Ok(file.face_vector)
}

pub fn read_nfc_attributes_from_json(file_path: &str) -> Result<NfcAttributesVector, Box<dyn Error>> {
    let json_content = fs::read_to_string(file_path)?;
    let file: NfcAttributesFile = serde_json::from_str(&json_content)?;
    Ok(file.nfc_attributes_vector)
}

#[test]
fn test_read_face_vector_from_json() {
    let face_enroll_vector = read_face_vector_from_json("/home/kali/projects/humanvault-sdk/mocks/Face_Mock_Enroll.json").unwrap();
    assert_eq!(face_enroll_vector.len(), 8);
    assert_eq!(face_enroll_vector[0], 0.4512);
    assert_eq!(face_enroll_vector[1], 0.8954);
    let face_auth_vector = read_face_vector_from_json("/home/kali/projects/humanvault-sdk/mocks/Face_Mock_Auth.json").unwrap();
    assert_eq!(face_auth_vector.len(), 8);
}