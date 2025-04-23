use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Result};
use rand::{rngs::OsRng, TryRngCore};
use std::fs;

pub fn encrypt_bytes(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        bail!("Key must be exactly 32 bytes");
    }

    let cipher = Aes256Gcm::new(key.into());

    // Generate a random 96-bit nonce (12 bytes)
    let mut nonce_bytes = [0u8; 12];
    OsRng.try_fill_bytes(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the plaintext
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    // Combine nonce and ciphertext for output
    let mut output = nonce_bytes.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn encrypt_string(plaintext: &str, key: &[u8]) -> Result<Vec<u8>> {
    encrypt_bytes(plaintext.as_bytes(), key)
}

pub fn decrypt_bytes(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        bail!("Key must be exactly 32 bytes");
    }
    if encrypted.len() < 12 {
        bail!("Encrypted data too short");
    }

    let cipher = Aes256Gcm::new(key.into());

    // Split the input into nonce and ciphertext
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];

    // Decrypt the ciphertext
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("Decryption failed: {}", e))
}

pub fn decrypt_string(encrypted: &[u8], key: &[u8]) -> Result<String> {
    let plaintext_bytes = decrypt_bytes(encrypted, key)?;
    Ok(String::from_utf8(plaintext_bytes)?)
}

pub fn decrypt_file(filename: &str, password_b64: &str) -> Result<Vec<u8>> {
    let data = fs::read(filename)?;
    let key = base64::decode(password_b64)?;
    decrypt_bytes(&data, &key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<()> {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key)?;

        let message = "Hello, world!";
        let encrypted = encrypt_string(message, &key).expect("Encryption should succeed");

        // Encrypted data should be longer than original due to nonce
        assert!(encrypted.len() > message.len());
        // First 12 bytes should be the nonce
        assert_eq!(encrypted.len(), message.len() + 12 + 16); // +16 for GCM tag

        let decrypted = decrypt_string(&encrypted, &key).expect("Decryption should succeed");
        assert_eq!(message, decrypted);

        // Test decryption fails with wrong key
        let mut wrong_key = [0u8; 32];
        OsRng.try_fill_bytes(&mut wrong_key)?;
        assert!(decrypt_string(&encrypted, &wrong_key).is_err());
        Ok(())
    }
}
