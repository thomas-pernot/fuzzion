use core::ptr::write_volatile;
use zeroize::Zeroize;
pub struct SecureVaultBuffer {
 buffer: Vec<u8>,
 capacity: usize,
}
impl SecureVaultBuffer {
 pub fn new(capacity: usize) -> Self {
 let mut buffer = Vec::with_capacity(capacity);
 buffer.resize(capacity, 0);
 SecureVaultBuffer { buffer, capacity }
 }
 pub fn get_pointer(&self) -> usize {
 self.buffer.as_ptr() as usize
 }
 pub fn write_bytes(&mut self, data: &[u8]) -> usize {
 let write_len = data.len().min(self.capacity);
 self.buffer[..write_len].copy_from_slice(&data[..write_len]);
 write_len
 }
 pub fn as_slice(&self) -> &[u8] {
 &self.buffer
 }
 /// ZÉROÏSATION SYNCHRONE : Écrase physiquement chaque octet par 0x00
 pub fn zeroize_deterministic(&mut self) -> bool {
 let slice = self.buffer.as_mut_slice();
 for byte in slice.iter_mut() {
 unsafe {
 write_volatile(byte, 0x00);
 }
 }
 self.buffer.zeroize();
 self.buffer.iter().all(|&b| b == 0x00)
 }
}
#[cfg(test)]
mod tests {
 use super::*;
 #[test]
 fn test_synchronous_ram_zeroization() {
 let mut vault = SecureVaultBuffer::new(32);
 let secret_key = [0xbe, 0x8e, 0x02, 0x46, 0xc4, 0x12, 0x40, 0xaa];
 assert_eq!(vault.write_bytes(&secret_key), 8);
 assert_eq!(vault.as_slice()[0], 0xbe);
 assert!(vault.zeroize_deterministic());
 assert!(vault.as_slice().iter().all(|&b| b == 0x00));
 }
}
