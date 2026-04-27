use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use num_bigint::BigUint;
use rand::Rng;
use sha2::{Digest, Sha256};
use pqc_kyber::{PublicKey, SecretKey, KYBER_CIPHERTEXTBYTES};
use pqc_kyber::*;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub struct LockResult {
    pub c: Vec<u8>,
    pub e: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub fn setup_key() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let lattice_key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let mut hasher = Sha256::new();
    hasher.update(&lattice_key);
    hasher.finalize().to_vec()
}

pub fn aes_encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes".to_string());
    }

    let mut rng = rand::thread_rng();
    let iv: [u8; 16] = rng.gen();
    
    // Create buffer with padding
    let block_size = 16;
    let padding_len = block_size - (plaintext.len() % block_size);
    let total_len = plaintext.len() + padding_len;
    let mut buffer = vec![0u8; total_len];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    
    let cipher = Aes256CbcEnc::new(key.into(), &iv.into());
    let ciphertext = cipher.encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|e| format!("Encryption error: {:?}", e))?;

    let mut result = iv.to_vec();
    result.extend_from_slice(ciphertext);
    Ok(result)
}

pub fn aes_decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes".to_string());
    }
    if ciphertext.len() < 16 {
        return Err("Ciphertext too short".to_string());
    }

    let iv = &ciphertext[..16];
    let encrypted = &ciphertext[16..];

    let cipher = Aes256CbcDec::new(key.into(), iv.into());
    let mut buffer = encrypted.to_vec();
    cipher.decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
        .map(|p| p.to_vec())
        .map_err(|e| format!("Decryption error: {:?}", e))
}

pub fn mod_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exponent, modulus)
}

pub fn bytes_to_biguint(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

pub fn biguint_to_bytes(n: &BigUint, length: usize) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    if bytes.len() > length {
        bytes[bytes.len() - length..].to_vec()
    } else if bytes.len() < length {
        let mut padded = vec![0u8; length - bytes.len()];
        padded.extend_from_slice(&bytes);
        padded
    } else {
        bytes
    }
}

pub fn lock_message(
    message: &[u8],
    t: usize,
    n: &BigUint,
    a: &BigUint,
    k: &[u8],
    receiver_pk: &PublicKey,
) -> Result<LockResult, String> {
    // Encrypt message with AES
    let c = aes_encrypt(message, &k[..32])?;
    
    // Convert key to BigUint
    let s = bytes_to_biguint(&k[..32]);
    
    // Compute time-lock puzzle
    let mut x = a.clone();
    let two = BigUint::from(2u32);
    
    for _ in 0..t {
        x = mod_pow(&x, &two, n);
    }
    
    let e_raw = (s + x) % n;
    
    // Encapsulate with ML-KEM using pqc_kyber
    let mut rng = rand::thread_rng();
    let (ct, ss) = encapsulate(receiver_pk, &mut rng)
        .map_err(|e| format!("Encapsulation failed: {:?}", e))?;
    
    // Encrypt E_Raw with shared secret
    let e_raw_bytes = e_raw.to_string().into_bytes();
    let e = aes_encrypt(&e_raw_bytes, &ss[..32])?;
    
    // ct is [u8; KYBER_CIPHERTEXTBYTES] which is 1088 bytes for Kyber768
    Ok(LockResult {
        c,
        e,
        ciphertext: ct.to_vec(),
    })
}

pub fn unlock_key(
    e: &[u8],
    a: &BigUint,
    n: &BigUint,
    t: usize,
    ciphertext: &[u8],
    receiver_sk: &SecretKey,
) -> Result<Vec<u8>, String> {
    // Decapsulate with ML-KEM
    if ciphertext.len() != KYBER_CIPHERTEXTBYTES {
        return Err(format!("Invalid ciphertext size: expected {}, got {}", 
            KYBER_CIPHERTEXTBYTES, ciphertext.len()));
    }
    
    let mut ct = [0u8; KYBER_CIPHERTEXTBYTES];
    ct.copy_from_slice(ciphertext);
    
    let ss = decapsulate(&ct, receiver_sk)
        .map_err(|e| format!("Decapsulation failed: {:?}", e))?;
    
    // Decrypt E with shared secret
    let e_raw_bytes = aes_decrypt(e, &ss[..32])?;
    let e_raw_str = String::from_utf8(e_raw_bytes)
        .map_err(|_| "Invalid UTF-8")?;
    let e_raw = e_raw_str.parse::<BigUint>()
        .map_err(|_| "Invalid BigUint")?;
    
    // Solve time-lock puzzle with visual progress bar
    let mut x = a.clone();
    let two = BigUint::from(2u32);
    
    // Print progress bar header
    print!("\r");
    use std::io::{self, Write};
    io::stdout().flush().unwrap();
    
    let bar_width = 40;
    let update_interval = if t > 100 { t / 100 } else { 1 };
    
    for i in 0..t {
        x = mod_pow(&x, &two, n);
        
        if i % update_interval == 0 || i == t - 1 {
            let progress = ((i + 1) as f64 / t as f64 * 100.0) as usize;
            let filled = (progress * bar_width / 100).min(bar_width);
            let empty = bar_width - filled;
            
            print!("\r[{}>{}] {}%",
                "=".repeat(filled),
                " ".repeat(empty),
                progress
            );
            io::stdout().flush().unwrap();
        }
    }
    println!(); // New line after progress bar
    
    let s_prime = if e_raw >= x {
        (e_raw - x) % n
    } else {
        (n + e_raw - x) % n
    };
    
    Ok(biguint_to_bytes(&s_prime, 32))
}

pub fn unlock_message(
    c: &[u8],
    e: &[u8],
    a: &BigUint,
    n: &BigUint,
    t: usize,
    ciphertext: &[u8],
    receiver_sk: &SecretKey,
) -> Result<Vec<u8>, String> {
    let k_prime = unlock_key(e, a, n, t, ciphertext, receiver_sk)?;
    aes_decrypt(c, &k_prime)
}
