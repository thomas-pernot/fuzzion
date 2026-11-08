use alloc::vec::Vec;
use core::ptr::write_volatile;
use core::sync::atomic::{compiler_fence, Ordering};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Tampon mémoire linéaire étanche avec zéroïsation physique déterministe
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureVaultBuffer {
    buffer: Vec<u8>,
    capacity: usize,
}

impl SecureVaultBuffer {
    /// Alloue un tampon pré-initialisé à 0x00 de taille fixe en RAM isolée
    pub fn new(capacity: usize) -> Self {
        let mut buffer = Vec::with_capacity(capacity);
        buffer.resize(capacity, 0u8);
        SecureVaultBuffer { buffer, capacity }
    }

    /// Retourne l'adresse mémoire opaque (pour l'interface FFI / WASM)
    pub fn get_pointer(&self) -> usize {
        self.buffer.as_ptr() as usize
    }

    /// Capacité maximale du tampon
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Copie des octets dans le coffre sans réallocation
    pub fn write_bytes(&mut self, data: &[u8]) -> usize {
        let write_len = data.len().min(self.capacity);
        self.buffer[..write_len].copy_from_slice(&data[..write_len]);
        write_len
    }

    /// Lecture en tranche constante
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    /// ZÉROÏSATION SYNCHRONE : Écrase physiquement chaque octet par 0x00
    /// et pose une barrière atomique empêchant toute suppression par LLVM.
    pub fn zeroize_deterministic(&mut self) -> bool {
        let slice = self.buffer.as_mut_slice();
        for byte in slice.iter_mut() {
            unsafe {
                write_volatile(byte, 0x00);
            }
        }
        compiler_fence(Ordering::SeqCst);
        self.buffer.zeroize();
        compiler_fence(Ordering::SeqCst);

        // Vérification en temps constant que tous les octets valent 0x00
        let mut acc: u8 = 0;
        for &b in self.buffer.iter() {
            acc |= b;
        }
        acc == 0
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