mod crypt;

use std::env;
use dotenv::dotenv;
use crypt::*;
use sha3::{Digest, Sha3_256};

fn main() {
    match dotenv() {
        Ok(path) => println!("Loaded .env from: {:?}", path),
        Err(e) => println!("Warning: Could not load .env: {}", e),
    }
    
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: vda <command>");
        println!();
        println!("Commands:");
        println!("  decrypt <domain> <epoch_id>    Decrypt next fragment using beacon from next fdr/dpr");
        println!("  reconstruct <domain> <epoch_id> Reconstruct private key using permute ordering");
        println!("  publish                        Combine recon.txt and commitment.txt into disclosure.txt");
        println!("  VerifyCommit <domain> <epoch_id> Verify disclosure commitment using reconstructed key");
        println!("  VerifySign                     Verify EdDSA signature from signature.txt");
        println!("  storage                        Display storage requirements for VDA artifacts");
        println!();
        println!("Notes:");
        println!("  - Decrypt processes one fragment per call");
        println!("  - Fragment i can only be decrypted when fdr_(i+1) exists (provides beacon)");
        println!("  - Last fragment requires dpr.txt to exist (provides beacon)");
        println!("  - Reconstruct reads permute.txt to order decrypt_N.txt files");
        return;
    }
    
    match args[1].as_str() {
        "decrypt" => {
            if args.len() < 4 {
                println!("Usage: vda decrypt <domain> <epoch_id>");
                return;
            }
            decrypt_fragment(&args[2], &args[3]);
        }
        "reconstruct" => {
            if args.len() < 4 {
                println!("Usage: vda reconstruct <domain> <epoch_id>");
                return;
            }
            reconstruct_private_key(&args[2], &args[3]);
        }
        "publish" => publish_disclosure(),
        "VerifyCommit" => {
            if args.len() < 4 {
                println!("Usage: vda VerifyCommit <domain> <epoch_id>");
                return;
            }
            verify_commitment(&args[2], &args[3]);
        }
        "VerifySign" => verify_signature(),
        "storage" => show_vda_storage(),
        _ => {
            println!("Unknown command. Run 'vda' without arguments for help.");
        }
    }
}

struct DomainConfig {
    num_fragments: usize,
}

fn read_domain_config(domain: &str) -> Option<DomainConfig> {
    let content = std::fs::read_to_string("NAEF/init.json").ok()?;
    for entry in content.split('{').skip(1) {
        let mut d = String::new();
        let mut nf = String::from("5");
        for part in entry.split(',') {
            let clean = part.replace('}', "").replace(']', "").replace('\n', "");
            let clean = clean.trim();
            if let Some((key, val)) = clean.split_once(':') {
                let key = key.trim().trim_matches('"');
                let val = val.trim().trim_matches('"');
                match key {
                    "domain" => d = val.to_string(),
                    "num_fragments" => nf = val.to_string(),
                    _ => {}
                }
            }
        }
        if d == domain {
            return Some(DomainConfig {
                num_fragments: nf.parse().unwrap_or(5),
            });
        }
    }
    None
}

fn decrypt_fragment(domain: &str, epoch_id: &str) {

    let config = match read_domain_config(domain) {
        Some(c) => c,
        None => {
            println!("Error: Domain '{}' not found in NAEF/init.json.", domain);
            return;
        }
    };

    let epoch_folder = format!("NAEF/{}/{}", domain.replace('.', "_"), epoch_id);
    let num_fragments = config.num_fragments;

    // Count existing decrypt files
    let mut decrypted = 0;
    for i in 1..=num_fragments {
        if std::path::Path::new(&format!("{}/decrypt_{}.txt", epoch_folder, i)).exists() {
            decrypted += 1;
        }
    }

    if decrypted >= num_fragments {
        println!("All {} fragments already decrypted for {}/{}", num_fragments, domain, epoch_id);
        return;
    }

    let next_seq = decrypted + 1; // 1-based sequence to decrypt

    // Read the fdr for this sequence
    let fdr_path = format!("{}/fdr_{}.txt", epoch_folder, next_seq);
    let fdr_content = match std::fs::read_to_string(&fdr_path) {
        Ok(c) => c,
        Err(_) => {
            println!("Error: {} not found.", fdr_path);
            return;
        }
    };

    let mut pkfragment = String::new();
    for line in fdr_content.lines() {
        if let Some(v) = line.strip_prefix("pkfragment:") {
            pkfragment = v.trim().to_string();
        }
    }

    if pkfragment.is_empty() {
        println!("Error: pkfragment not found in {}", fdr_path);
        return;
    }

    // Get the vrf_output to use as decryption key
    // fdr_1 was encrypted with VRF of ebr_1's beacon
    // fdr_(i+1) contains vrf_output for ebr_i
    // dpr.txt contains vrf_output for ebr_last

    let vrf_output_hex = if next_seq < num_fragments {
        let next_fdr_path = format!("{}/fdr_{}.txt", epoch_folder, next_seq + 1);
        match std::fs::read_to_string(&next_fdr_path) {
            Ok(content) => {
                let mut v = String::new();
                for line in content.lines() {
                    if let Some(val) = line.strip_prefix("vrf_output:") {
                        v = val.trim().to_string();
                    }
                }
                if v.is_empty() {
                    println!("Error: vrf_output not found in {}. Need fdr_{} to decrypt fdr_{}.",
                        next_fdr_path, next_seq + 1, next_seq);
                    return;
                }
                v
            }
            Err(_) => {
                println!("Error: {} not found. Cannot decrypt fdr_{} without fdr_{}.",
                    next_fdr_path, next_seq, next_seq + 1);
                return;
            }
        }
    } else {
        let dpr_path = format!("{}/dpr.txt", epoch_folder);
        match std::fs::read_to_string(&dpr_path) {
            Ok(content) => {
                let mut v = String::new();
                for line in content.lines() {
                    if let Some(val) = line.strip_prefix("vrf_output:") {
                        v = val.trim().to_string();
                    }
                }
                if v.is_empty() {
                    println!("Error: vrf_output not found in dpr.txt.");
                    return;
                }
                v
            }
            Err(_) => {
                println!("Error: dpr.txt not found in {}. Cannot decrypt last fragment without DPR.", epoch_folder);
                return;
            }
        }
    };

    let k = hex::decode(&vrf_output_hex).expect("Invalid vrf_output hex");

    let c_bytes = hex::decode(&pkfragment).expect("Invalid pkfragment hex");

    match aes_decrypt(&c_bytes, &k) {
        Ok(recovered) => {
            let recovered_str = String::from_utf8_lossy(&recovered).to_string();
            let decrypt_path = format!("{}/decrypt_{}.txt", epoch_folder, next_seq);
            std::fs::write(&decrypt_path, &recovered_str).expect("Failed to write decrypt file");
            println!("Fragment {}/{} decrypted", next_seq, num_fragments);
            println!("Saved to {}", decrypt_path);
        }
        Err(e) => println!("Error decrypting fragment {}: {}", next_seq, e),
    }
}

fn reconstruct_private_key(domain: &str, epoch_id: &str) {
    let config = match read_domain_config(domain) {
        Some(c) => c,
        None => {
            println!("Error: Domain '{}' not found in NAEF/init.json.", domain);
            return;
        }
    };

    let epoch_folder = format!("NAEF/{}/{}", domain.replace('.', "_"), epoch_id);
    let num_fragments = config.num_fragments;

    // Read permutation from dpr.txt
    let dpr_path = format!("{}/dpr.txt", epoch_folder);
    let dpr_content = match std::fs::read_to_string(&dpr_path) {
        Ok(c) => c,
        Err(_) => {
            println!("Error: {} not found. Run 'kda dpr' first.", dpr_path);
            return;
        }
    };

    let mut permutation_str = String::new();
    for line in dpr_content.lines() {
        if let Some(v) = line.strip_prefix("permutation:") {
            permutation_str = v.trim().to_string();
        }
    }

    let order: Vec<usize> = permutation_str
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    if order.len() != num_fragments {
        println!("Error: dpr.txt permutation has {} entries, expected {}", order.len(), num_fragments);
        return;
    }

    // decrypt_seq contains key part order[seq-1]
    // We need parts in order 1,2,3,...,n
    let mut parts = vec![String::new(); num_fragments];
    for seq in 1..=num_fragments {
        let decrypt_path = format!("{}/decrypt_{}.txt", epoch_folder, seq);
        let content = match std::fs::read_to_string(&decrypt_path) {
            Ok(c) => c,
            Err(_) => {
                println!("Error: {} not found. Decrypt all fragments first.", decrypt_path);
                return;
            }
        };
        let part_index = order[seq - 1] - 1;
        parts[part_index] = content;
    }

    let private_key = parts.join("");
    let recon_path = format!("{}/recon.txt", epoch_folder);
    std::fs::write(&recon_path, &private_key).expect("Failed to write recon.txt");
    println!("Private key reconstructed");
    println!("Saved to {}", recon_path);
}

fn verify_commitment(domain: &str, epoch_id: &str) {
    println!("Verifying disclosure commitment...");

    let epoch_folder = format!("NAEF/{}/{}", domain.replace('.', "_"), epoch_id);
    
    let commitment_content = match std::fs::read_to_string(format!("{}/commitment.txt", epoch_folder)) {
        Ok(content) => content,
        Err(_) => {
            println!("Error: commitment.txt not found in {}", epoch_folder);
            return;
        }
    };
    
    let mut hash_from_file = String::new();
    let mut encrypted_text = String::new();
    
    for line in commitment_content.lines() {
        if line.starts_with("SHA3-256 Hash:") {
            hash_from_file = line.trim_start_matches("SHA3-256 Hash:").trim().to_string();
        } else if line.starts_with("Encrypted Text:") {
            encrypted_text = line.trim_start_matches("Encrypted Text:").trim().to_string();
        }
    }
    
    if hash_from_file.is_empty() || encrypted_text.is_empty() {
        println!("Error: Invalid commitment file format");
        return;
    }
    
    println!("Hash from commitment: {}", hash_from_file);
    let private_key_b64 = match std::fs::read_to_string(format!("{}/recon.txt", epoch_folder)) {
        Ok(key) => key,
        Err(_) => {
            println!("Error: recon.txt not found in {}. Run reconstruct first.", epoch_folder);
            return;
        }
    };
    
    let mut pem_body = String::new();
    for (i, chunk) in private_key_b64.trim().as_bytes().chunks(64).enumerate() {
        if i > 0 {
            pem_body.push('\n');
        }
        pem_body.push_str(&String::from_utf8_lossy(chunk));
    }
    let private_key_pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", pem_body);
    
    use rsa::{RsaPrivateKey, Pkcs1v15Encrypt};
    use rsa::pkcs8::DecodePrivateKey;
    
    let private_key = match RsaPrivateKey::from_pkcs8_pem(&private_key_pem) {
        Ok(key) => key,
        Err(e) => {
            println!("Error parsing private key: {}", e);
            return;
        }
    };
    
    let encrypted_bytes = match hex::decode(&encrypted_text) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("Error decoding encrypted text: {}", e);
            return;
        }
    };
    
    let decrypted_bytes = match private_key.decrypt(Pkcs1v15Encrypt, &encrypted_bytes) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("Error decrypting: {}", e);
            return;
        }
    };
    
    let decrypted_text = match String::from_utf8(decrypted_bytes) {
        Ok(text) => text,
        Err(e) => {
            println!("Error converting decrypted bytes to text: {}", e);
            return;
        }
    };
    
    println!("Decrypted text: {}", decrypted_text);
    
    let mut hasher = Sha3_256::new();
    hasher.update(decrypted_text.as_bytes());
    let computed_hash = hasher.finalize();
    let computed_hash_hex = hex::encode(computed_hash);
    
    println!("Computed hash: {}", computed_hash_hex);
    
    if computed_hash_hex == hash_from_file {
        println!("\n✓ VERIFICATION SUCCESSFUL");
        println!("  Original text: {}", decrypted_text);
        println!("  Hash matches: {}", hash_from_file);
    } else {
        println!("\n✗ VERIFICATION FAILED");
        println!("  Expected hash: {}", hash_from_file);
        println!("  Computed hash: {}", computed_hash_hex);
    }
}

fn verify_signature() {
    println!("Verifying EdDSA signature...");
    
    let signature_content = match std::fs::read_to_string("signature.txt") {
        Ok(content) => content,
        Err(_) => {
            println!("Error: signature.txt not found");
            return;
        }
    };
    
    let mut random_text = String::new();
    let mut public_key_hex = String::new();
    let mut signature_hex = String::new();
    
    for line in signature_content.lines() {
        if line.starts_with("Random Text:") {
            random_text = line.trim_start_matches("Random Text:").trim().to_string();
        } else if line.starts_with("Public Key:") {
            public_key_hex = line.trim_start_matches("Public Key:").trim().to_string();
        } else if line.starts_with("Signature:") {
            signature_hex = line.trim_start_matches("Signature:").trim().to_string();
        }
    }
    
    if random_text.is_empty() || public_key_hex.is_empty() || signature_hex.is_empty() {
        println!("Error: Invalid signature file format");
        return;
    }
    
    println!("Random text: {}", random_text);
    println!("Public key: {}", public_key_hex);
    println!("Signature: {}...", &signature_hex[..20.min(signature_hex.len())]);
    
    use ed25519_dalek::{VerifyingKey, Signature, Verifier};
    
    let public_key_bytes = hex::decode(&public_key_hex).expect("Invalid public key hex");
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes.as_slice().try_into().unwrap())
        .expect("Invalid public key");
    let signature_bytes = hex::decode(&signature_hex).expect("Invalid signature hex");
    let signature = Signature::from_bytes(&signature_bytes.as_slice().try_into().unwrap());
    
    match verifying_key.verify(random_text.as_bytes(), &signature) {
        Ok(_) => {
            println!("\n✓ SIGNATURE VERIFICATION SUCCESSFUL");
            println!("  Original text: {}", random_text);
        }
        Err(_) => {
            println!("\n✗ SIGNATURE VERIFICATION FAILED");
        }
    }
}

fn publish_disclosure() {
    let private_key = match std::fs::read_to_string("recon.txt") {
        Ok(key) => key,
        Err(_) => {
            println!("Error: recon.txt not found. Run reconstruct command first.");
            return;
        }
    };
    
    let commitment = match std::fs::read_to_string("commitment.txt") {
        Ok(content) => content,
        Err(_) => {
            println!("Error: commitment.txt not found");
            return;
        }
    };
    
    let disclosure = format!("Private Key:\n{}\n\nCommitment:\n{}", private_key, commitment);
    std::fs::write("disclosure.txt", disclosure).expect("Failed to write disclosure.txt");
    
    println!("Disclosure published to disclosure.txt");
}

fn show_vda_storage() {
    println!("=== VDA Storage Requirements ===");
    println!();
    
    let mut total_size = 0u64;
    
    // Check fragment files (1-5)
    let mut fragment_total = 0u64;
    let mut fragment_count = 0;
    for i in 1..=5 {
        let filename = format!("fragment_{}.txt", i);
        if let Ok(metadata) = std::fs::metadata(&filename) {
            let size = metadata.len();
            fragment_total += size;
            fragment_count += 1;
            println!("fragment_{}.txt:         {:>8} bytes  (Encrypted key fragment)", i, size);
        }
    }
    if fragment_count == 0 {
        println!("fragment_*.txt:         Not found");
    }
    total_size += fragment_total;
    
    // Check reconstruct files (1-5)
    let mut reconstruct_total = 0u64;
    let mut reconstruct_count = 0;
    for i in 1..=5 {
        let filename = format!("reconstruct_{}.txt", i);
        if let Ok(metadata) = std::fs::metadata(&filename) {
            let size = metadata.len();
            reconstruct_total += size;
            reconstruct_count += 1;
            println!("reconstruct_{}.txt:      {:>8} bytes  (Decrypted key fragment)", i, size);
        }
    }
    if reconstruct_count == 0 {
        println!("reconstruct_*.txt:      Not found");
    }
    total_size += reconstruct_total;
    
    if let Ok(metadata) = std::fs::metadata("permute.txt") {
        let size = metadata.len();
        total_size += size;
        println!("permute.txt:            {:>8} bytes  (Fragment permutation order)", size);
    }
    
    if let Ok(metadata) = std::fs::metadata("recon.txt") {
        let size = metadata.len();
        total_size += size;
        println!("recon.txt:              {:>8} bytes  (Reconstructed private key)", size);
    }
    
    if let Ok(metadata) = std::fs::metadata("commitment.txt") {
        let size = metadata.len();
        total_size += size;
        println!("commitment.txt:         {:>8} bytes  (Disclosure commitment)", size);
    }
    
    if let Ok(metadata) = std::fs::metadata("disclosure.txt") {
        let size = metadata.len();
        total_size += size;
        println!("disclosure.txt:         {:>8} bytes  (Published disclosure)", size);
    }
    
    println!();
    println!("Total VDA Storage:      {:>8} bytes  ({:.2} KB)", total_size, total_size as f64 / 1024.0);
}
