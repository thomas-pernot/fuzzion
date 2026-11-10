use serde::Deserialize;
use std::{collections::HashMap, error::Error, fs};

pub type FaceVector = Vec<f32>;
pub type NfcAttributesVector = HashMap<String, i128>;

#[derive(Deserialize)]
struct FaceVectorFile {
    #[serde(alias = "face_master_vector", alias = "face_new_vector")]
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

#[cfg(test)]

#[test]
fn test_read_face_vector_from_json() {
    let enroll_path = concat!(env!("CARGO_MANIFEST_DIR"), "/mocks/Face_Mock_Enroll.json");
    let face_enroll_vector = read_face_vector_from_json(enroll_path).unwrap();
    assert_eq!(face_enroll_vector.len(), 8);
    assert_eq!(face_enroll_vector[0], 0.4512);
    assert_eq!(face_enroll_vector[1], 0.8954);
    let auth_path = concat!(env!("CARGO_MANIFEST_DIR"), "/mocks/Face_Mock_Auth.json");
    let face_auth_vector = read_face_vector_from_json(auth_path).unwrap();
    assert_eq!(face_auth_vector.len(), 8);
}