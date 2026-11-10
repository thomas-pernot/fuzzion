use serde::Deserialize;
use std::{error::Error, fs};

pub type FaceVector = Vec<f32>;
pub type NfcSignatureVector = Vec<f32>;

#[derive(Deserialize)]
pub struct FaceVectorFile {
    #[serde(alias = "face_master_vector", alias = "face_new_vector")]
    pub face_vector: Vec<f32>
}

#[derive(Deserialize)]
pub struct NfcSignatureVectorFile {
    pub nfc_signature_vector: NfcSignatureVector,
}

#[derive(Deserialize)]
pub struct NfcCertifiedAttributes {
    pub birth_timestamp: i128,
    pub residence_country_iso: u16,
    pub monthly_net_salary_eur: i128,
    pub document_expiry_timestamp: i128
}

#[derive(Deserialize)]
pub struct NfcAttributesFile {
    pub nfc_signature_vector: NfcSignatureVector,
    pub certified_attributes: NfcCertifiedAttributes
}

pub fn read_face_vector_from_json(file_path: &str) -> Result<FaceVector, Box<dyn Error>> {
    let json_content = fs::read_to_string(file_path)?;
    let file: FaceVectorFile = serde_json::from_str(&json_content)?;
    Ok(file.face_vector)
}

pub fn read_nfc_attributes_from_json(file_path: &str) -> Result<(NfcSignatureVector, NfcCertifiedAttributes), Box<dyn Error>> {
    let json_content = fs::read_to_string(file_path)?;
    let file: NfcAttributesFile = serde_json::from_str(&json_content)?;
    Ok((file.nfc_signature_vector, file.certified_attributes))
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

#[test]
fn test_read_nfc_attributes_from_json() {
    let nfc_path = concat!(env!("CARGO_MANIFEST_DIR"), "/mocks/NFC_And_Docs_Mock.json");
    let (nfc_signature_vector, certified_attributes) = read_nfc_attributes_from_json(nfc_path).unwrap();
    assert_eq!(nfc_signature_vector.len(), 8);
    assert_eq!(nfc_signature_vector[0], 0.1245);
    assert_eq!(certified_attributes.birth_timestamp, 946684800);
    assert_eq!(certified_attributes.residence_country_iso, 250);
    assert_eq!(certified_attributes.monthly_net_salary_eur, 2450);
    assert_eq!(certified_attributes.document_expiry_timestamp, 1956528000);
}