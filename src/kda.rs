mod crypt;

use std::env;
use std::thread;
use std::time::Duration;
use dotenv::dotenv;
use pqc_kyber::*;
use crypt::*;
use num_bigint::BigUint;
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use rand::Rng;
use sha3::{Digest, Sha3_256};

fn main() {
    match dotenv() {
        Ok(path) => println!("Loaded .env from: {:?}", path),
        Err(e) => println!("Warning: Could not load .env: {}", e),
    }
    
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: kda <command>");
        println!();
        println!("Lifecycle Commands (run in order):");
        println!("  init <domain> <epoch> <selector> [n] [fah] Initialize domain config (n=fragments default 5, fah default 5)");
        println!("  epr <domain>                        Create next epoch with RSA+VRF keys and EPR file");
        println!("  eka <domain> <epoch_id>              Generate Epoch Key Activation for domain/epoch");
        println!("  kdr <domain> <epoch_id>              Generate Key Disclosure Request with commitment");
        println!("  fragment <domain> <epoch_id>         Encrypt next key fragment (one per call)");
        println!("  dpr <domain> <epoch_id>              Generate Disclosure Publication Request");
        println!();
        println!("Utility Commands:");
        println!("  showkey <domain> <epoch_id> [private|public]  Display key for domain/epoch");
        println!("  permute <domain> <epoch_id> [n]      Generate random permutation (auto-called by fragment)");
        println!("  tebsLookup [epoch_time]             Lookup TEBS beacon (default: latest)");
        println!("  storage                             Display storage requirements");
        println!();
        println!("Legacy Commands:");
        println!("  keygen                              Generate standalone RSA 4096-bit key pair");
        println!("  commit                              Generate standalone disclosure commitment");
        println!("  sign                                Sign random text with EdDSA key");
        println!("  kda-metrics-sign [N] [idx] [f] [s]  Run EdDSA signing performance metrics");
        println!("                                        N=requests idx=key_index f=filename s=index_size");
        println!();
        println!("Notes:");
        println!("  - epr auto-increments epoch_id (epoch_interval from init config)");
        println!("  - Fragment encryption uses VRF(beacon) as AES key via Ed25519 signing");
        println!("  - TEBS service must be running before using fragment command");
        println!("  - Each fragment call processes one fragment in permute order");
        println!("  - Fragment stops when num_fragments from init config is reached");
        return;
    }
    
    match args[1].as_str() {
        "keygen" => generate_keypair(),
        "showkey" => {
            if args.len() < 4 {
                println!("Usage: kda showkey <domain> <epoch_id> [private|public]");
                return;
            }
            let key_type = args.get(4).map(|s| s.as_str()).unwrap_or("private");
            show_key(&args[2], &args[3], key_type);
        }
        "fragment" => {
            if args.len() < 4 {
                println!("Usage: kda fragment <domain> <epoch_id>");
                return;
            }
            send_fragment(&args[2], &args[3]);
        }
        "commit" => generate_commitment(),
        "sign" => sign_text(),
        "permute" => {
            if args.len() < 4 {
                println!("Usage: kda permute <domain> <epoch_id> [n]");
                return;
            }
            let n = args.get(4)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(5);
            generate_permutation(&args[2], &args[3], n);
        }
        "kda-metrics-sign" => {
            let num_requests = args.get(2)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(1000);
            
            // Parse index - if it's "_" or non-numeric, treat as None
            let key_index = args.get(3)
                .and_then(|s| {
                    if s == "_" {
                        None
                    } else {
                        s.parse::<usize>().ok()
                    }
                });
            
            let filename = args.get(4)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "signing_metrics.csv".to_string());
            let index_size = args.get(5)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(96);
            metrics_sign(num_requests, key_index, filename, index_size);
        }
        "naef-metrics" => {
            let mut iterations = 1;
            for arg in args.iter().skip(2) {
                if arg.starts_with("n=") || arg.starts_with("N=") {
                    iterations = arg[2..].parse::<usize>().unwrap_or(1);
                }
            }
            run_naef_metrics(iterations);
        }
        "storage" => show_kda_storage(),
        "tebsLookup" => {
            let epoch_time = args.get(2).and_then(|s| s.parse::<u64>().ok());
            tebs_lookup(epoch_time);
        }
        "epr" => {
            let domain = args.get(2).unwrap_or_else(|| {
                println!("Usage: kda epr <domain>");
                std::process::exit(1);
            });
            generate_epr(domain);
        }
        "eka" => {
            if args.len() < 4 {
                println!("Usage: kda eka <domain> <epoch_id>");
                return;
            }
            generate_eka(&args[2], &args[3]);
        }
        "kdr" => {
            if args.len() < 4 {
                println!("Usage: kda kdr <domain> <epoch_id>");
                return;
            }
            generate_kdr(&args[2], &args[3]);
        }
        "dpr" => {
            if args.len() < 4 {
                println!("Usage: kda dpr <domain> <epoch_id>");
                return;
            }
            generate_dpr(&args[2], &args[3]);
        }
        "init" => {
            if args.len() < 5 {
                println!("Usage: kda init <domain> <epoch_interval_sec> <selector> [num_fragments] [fah]");
                return;
            }
            let num_fragments = args.get(5)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(5);
            let fah = args.get(6)
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(5);
            generate_init(&args[2], &args[3], &args[4], num_fragments, fah);
        }
        _ => {
            println!("Unknown command. Run 'kda' without arguments for help.");
        }
    }
}

fn generate_keypair() {
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    
    println!("Generating RSA key pair...");
    
    let mut rng = rand::thread_rng();
    let bits = 4096;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate private key");
    let public_key = RsaPublicKey::from(&private_key);
    
    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF).expect("Failed to encode private key");
    let public_pem = public_key.to_public_key_pem(LineEnding::LF).expect("Failed to encode public key");
    
    std::fs::write("private_key.pem", private_pem.as_bytes()).expect("Failed to write private key");
    std::fs::write("public_key.pem", public_pem.as_bytes()).expect("Failed to write public key");
    
    println!("Private key saved to private_key.pem");
    println!("Public key saved to public_key.pem");
}

fn show_key(domain: &str, epoch_id: &str, key_type: &str) {
    let epoch_folder = format!("NAEF/{}/{}", domain.replace('.', "_"), epoch_id);
    match key_type {
        "public" => {
            match std::fs::read_to_string(format!("{}/public_key.pem", epoch_folder)) {
                Ok(key) => println!("{}", key),
                Err(_) => println!("public_key.pem not found in {}. Run 'kda epr {}' first.", epoch_folder, domain),
            }
        }
        _ => {
            match std::fs::read_to_string(format!("{}/private_key.pem", epoch_folder)) {
                Ok(key) => println!("{}", key),
                Err(_) => println!("private_key.pem not found in {}. Run 'kda epr {}' first.", epoch_folder, domain),
            }
        }
    }
}

fn send_fragment(domain: &str, epoch_id: &str) {
    let config = match read_domain_config(domain) {
        Some(c) => c,
        None => {
            println!("Error: Domain '{}' not found in NAEF/init.json. Run 'kda init' first.", domain);
            return;
        }
    };

    let epoch_folder = format!("NAEF/{}/{}", domain.replace('.', "_"), epoch_id);
    let private_key_path = format!("{}/private_key.pem", epoch_folder);

    let private_key_pem = match std::fs::read_to_string(&private_key_path) {
        Ok(key) => key,
        Err(_) => {
            println!("Error: {} not found. Run 'kda epr {}' first.", private_key_path, domain);
            return;
        }
    };

    let private_key = private_key_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();

    let num_fragments = config.num_fragments;

    // Count existing fdr files to determine how many already processed
    let mut processed = 0;
    for i in 1..=num_fragments {
        if std::path::Path::new(&format!("{}/fdr_{}.txt", epoch_folder, i)).exists() {
            processed += 1;
        }
    }

    if processed >= num_fragments {
        println!("All {} fragments already created for {}/{}", num_fragments, domain, epoch_id);
        return;
    }

    // Generate permute if not exists
    let permute_path = format!("{}/permute.txt", epoch_folder);
    if !std::path::Path::new(&permute_path).exists() {
        generate_permutation(domain, epoch_id, num_fragments);
    }

    let perm_content = std::fs::read_to_string(&permute_path).expect("Failed to read permute.txt");
    let permutation: Vec<usize> = perm_content.trim()
        .split(',')
        .filter_map(|s| s.parse().ok())
        .collect();

    // The sequence index (0-based) is how many we've already done
    let seq_index = processed;
    let fragment_order = permutation[seq_index]; // which part of the key to extract
    let fragment_seq = seq_index + 1; // 1-based sequence number

    // Split key and extract the fragment_order-th part (1-based)
    let parts = split_into_n(&private_key, num_fragments);
    let part = &parts[fragment_order - 1];

    // Fetch latest TEBS beacon
    tebs_lookup(None);
    let tebs = read_tebs_beacon();
    if tebs.beacon.is_empty() {
        println!("Error: Could not read TEBS beacon. Is TEBS running?");
        return;
    }

    // Save beacon as ebr_<seq>.txt
    let ebr_path = format!("{}/ebr_{}.txt", epoch_folder, fragment_seq);
    let ebr_content = format!(
        "epoch:{}\nepoch_time:{}\ntimestamp:{}\nbeacon:{}\nproof:{}\n",
        tebs.epoch, tebs.epoch_time, tebs.timestamp, tebs.beacon, tebs.proof
    );
    std::fs::write(&ebr_path, &ebr_content).expect("Failed to write ebr file");

    // Compute VRF(beacon) using Ed25519 signing key
    use ed25519_dalek::{SigningKey as VrfSigningKey, Signer as VrfSigner};
    use sha2::{Sha256, Digest as Sha2Digest};
    let vrf_key_path = format!("{}/vrf_key.bin", epoch_folder);
    let vrf_secret = std::fs::read(&vrf_key_path)
        .expect("Failed to read vrf_key.bin. Run 'kda epr' first.");
    let mut vrf_bytes = [0u8; 32];
    vrf_bytes.copy_from_slice(&vrf_secret);
    let vrf_sk = VrfSigningKey::from_bytes(&vrf_bytes);
    let vrf_signature = vrf_sk.sign(tebs.beacon.as_bytes());
    let vrf_proof_hex = hex::encode(vrf_signature.to_bytes());
    // VRF output = SHA-256(signature) → 32 bytes for AES key
    let mut hasher = Sha256::new();
    hasher.update(vrf_signature.to_bytes());
    let vrf_output = hasher.finalize().to_vec();
    let vrf_output_hex = hex::encode(&vrf_output);

    let c = crypt::aes_encrypt(part.as_bytes(), &vrf_output)
        .expect("Failed to encrypt fragment");

    let mut rng = rand::thread_rng();
    let id: u64 = rng.gen_range(1111111111..9999999999);

    // Save as fdr_<seq>.txt
    // fdr_1 has no beacon; fdr_N contains ebr_(N-1) details
    let fdr_path = format!("{}/fdr_{}.txt", epoch_folder, fragment_seq);
    let fdr_content = if fragment_seq == 1 {
        format!(
            "pkfragment: {}\npkmlid: {}\nfragment_seq: {}\n",
            hex::encode(&c), id, fragment_seq
        )
    } else {
        let prev_ebr = read_ebr_file(&epoch_folder, fragment_seq - 1);
        // Compute VRF for previous beacon
        let prev_vrf_sig = vrf_sk.sign(prev_ebr.beacon.as_bytes());
        let mut prev_hasher = Sha256::new();
        prev_hasher.update(prev_vrf_sig.to_bytes());
        let prev_vrf_output = hex::encode(prev_hasher.finalize());
        let prev_vrf_proof = hex::encode(prev_vrf_sig.to_bytes());
        format!(
            "pkfragment: {}\npkmlid: {}\nfragment_seq: {}\nvrf_output: {}\nvrf_proof: {}\ntebs_epoch: {}\ntebs_epoch_time: {}\ntebs_timestamp: {}\ntebs_beacon: {}\ntebs_proof: {}\n",
            hex::encode(&c), id, fragment_seq,
            prev_vrf_output, prev_vrf_proof,
            prev_ebr.epoch, prev_ebr.epoch_time, prev_ebr.timestamp, prev_ebr.beacon, prev_ebr.proof
        )
    };
    std::fs::write(&fdr_path, &fdr_content).expect("Failed to write fdr file");

    println!("Fragment {}/{} created (order={})", fragment_seq, num_fragments, fragment_order);
    println!("  ebr: {}", ebr_path);
    println!("  fdr: {}", fdr_path);
}

fn read_ebr_file(epoch_folder: &str, seq: usize) -> TebsBeacon {
    let mut tb = TebsBeacon {
        epoch: String::new(), epoch_time: String::new(),
        timestamp: String::new(), beacon: String::new(), proof: String::new(),
    };
    let path = format!("{}/ebr_{}.txt", epoch_folder, seq);
    if let Ok(content) = std::fs::read_to_string(&path) {
        for line in content.lines() {
            if let Some(v) = line.strip_prefix("epoch:") { tb.epoch = v.trim().to_string(); }
            else if let Some(v) = line.strip_prefix("epoch_time:") { tb.epoch_time = v.trim().to_string(); }
            else if let Some(v) = line.strip_prefix("timestamp:") { tb.timestamp = v.trim().to_string(); }
            else if let Some(v) = line.strip_prefix("beacon:") { tb.beacon = v.trim().to_string(); }
            else if let Some(v) = line.strip_prefix("proof:") { tb.proof = v.trim().to_string(); }
        }
    }
    tb
}

fn split_into_n(s: &str, n: usize) -> Vec<String> {
    let len = s.len();
    let part_len = len / n;
    let remainder = len % n;
    let mut result = Vec::new();
    let mut start = 0;

    for i in 0..n {
        let mut end = start + part_len;
        if i < remainder {
            end += 1;
        }
        result.push(s[start..end].to_string());
        start = end;
    }
    result
}

fn split_into_five(s: &str) -> Vec<String> {
    split_into_n(s, 5)
}

fn send_email(c: &str, e: &str, ciphertext: &str, id: &str, seq: &str) -> Result<(), String> {
    let from = env::var("Mail_SMTP_FROM_ADDRESS").map_err(|_| "Mail_SMTP_FROM_ADDRESS not set")?;
    let to = env::var("Mail_CONSORTIUM_EMAIL").map_err(|_| "Mail_CONSORTIUM_EMAIL not set")?;
    let smtp_host = env::var("Mail_SMTP_HOST").map_err(|_| "Mail_SMTP_HOST not set")?;
    let smtp_user = env::var("MAIL_SMTP_USERNAME").map_err(|_| "MAIL_SMTP_USERNAME not set")?;
    let smtp_pass = env::var("MAIL_SMTP_PASSWORD").map_err(|_| "MAIL_SMTP_PASSWORD not set")?;

    let body = format!(
        "pkfragment: {}\npkcipher: {}\ntlpuzzle: {}\npkmlid: {}\npkseq: {}\n\nMAIL PRIVATE KEY PARTS",
        c, ciphertext, e, id, seq
    );
    
    let email = Message::builder()
        .from(from.parse().map_err(|_| "Invalid from address")?)
        .to(to.parse().map_err(|_| "Invalid to address")?)
        .subject("MAIL PRIVATE KEY")
        .body(body)
        .map_err(|e| format!("Failed to build email: {}", e))?;

    let creds = Credentials::new(smtp_user, smtp_pass);
    let mailer = SmtpTransport::relay(&smtp_host)
        .map_err(|e| format!("Failed to create SMTP transport: {}", e))?
        .credentials(creds)
        .build();

    mailer.send(&email)
        .map_err(|e| format!("Failed to send email: {}", e))?;

    Ok(())
}

fn generate_commitment() {
    use std::time::Instant;
    let start = Instant::now();
    
    println!("Generating disclosure commitment...");
    
    // Generate random 8-char alphanumeric text
    let mut rng = rand::thread_rng();
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let random_text: String = (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    
    println!("Random text: {}", random_text);
    
    // Compute SHA3-256 hash
    let mut hasher = Sha3_256::new();
    hasher.update(random_text.as_bytes());
    let hash = hasher.finalize();
    let hash_hex = hex::encode(hash);
    
    println!("SHA3-256 hash: {}", hash_hex);
    
    // Get RSA private key from file
    let private_key_pem = match std::fs::read_to_string("private_key.pem") {
        Ok(key) => key,
        Err(_) => {
            println!("Error: private_key.pem not found. Run keygen first.");
            return;
        }
    };
    
    // Encrypt with RSA public key
    use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
    use rsa::pkcs8::DecodePrivateKey;
    
    let private_key = match RsaPrivateKey::from_pkcs8_pem(&private_key_pem) {
        Ok(key) => key,
        Err(e) => {
            println!("Error parsing private key: {}", e);
            return;
        }
    };
    
    let public_key = RsaPublicKey::from(&private_key);
    
    let encrypted_bytes = match public_key.encrypt(&mut rng, Pkcs1v15Encrypt, random_text.as_bytes()) {
        Ok(enc) => enc,
        Err(e) => {
            println!("Error encrypting: {}", e);
            return;
        }
    };
    
    let encrypted_text = hex::encode(encrypted_bytes);
    
    println!("Encrypted text: {}", encrypted_text);
    
    // Save commitment to file (without encryption key since we use RSA)
    let commitment = format!(
        "Random Text: {}\nSHA3-256 Hash: {}\nEncrypted Text: {}\n",
        random_text, hash_hex, encrypted_text
    );
    
    std::fs::write("commitment.txt", commitment).expect("Failed to write commitment file");
    
    let duration = start.elapsed();
    println!("\nCommitment saved to commitment.txt");
    println!("\nDisclosure Commitment:");
    println!("  Hash: {}", hash_hex);
    println!("  Encrypted: {}", encrypted_text);
    println!("\nTime taken: {:.3}ms", duration.as_secs_f64() * 1000.0);
}

fn sign_text() {
    use std::time::Instant;
    let start = Instant::now();
    
    println!("Generating EdDSA signature...");
    
    let mut rng = rand::thread_rng();
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let random_text: String = (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    
    println!("Random text: {}", random_text);
    
    use ed25519_dalek::{SigningKey, Signer, SigningKey as Ed25519SigningKey};
    
    let mut secret_bytes = [0u8; 32];
    rng.fill(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(random_text.as_bytes());
    
    let signature_hex = hex::encode(signature.to_bytes());
    let public_key_hex = hex::encode(verifying_key.to_bytes());
    
    println!("Public key: {}", public_key_hex);
    println!("Signature: {}", signature_hex);
    
    let sign_data = format!(
        "Random Text: {}\nPublic Key: {}\nSignature: {}\n",
        random_text, public_key_hex, signature_hex
    );
    
    std::fs::write("signature.txt", sign_data).expect("Failed to write signature file");
    
    let duration = start.elapsed();
    println!("\nSignature saved to signature.txt");
    println!("\nTime taken: {:.3}ms", duration.as_secs_f64() * 1000.0);
}

fn metrics_sign(num_requests: usize, fixed_key_index: Option<usize>, filename: String, index_size: usize) {
    use std::time::Instant;
    use ed25519_dalek::{SigningKey, Signer};
    use std::fs::File;
    use std::io::Write;
    
    println!("Initializing signing metrics experiment...");
    
    // Generate signing keys based on index_size
    let mut rng = rand::thread_rng();
    let mut signing_keys = Vec::with_capacity(index_size);
    
    for _ in 0..index_size {
        let mut secret_bytes = [0u8; 32];
        rng.fill(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        signing_keys.push(signing_key);
    }
    
    println!("Generated {} signing keys", index_size);
    println!("Starting signing requests...\n");
    
    // Create CSV file
    let mut file = File::create(&filename).expect("Failed to create CSV file");
    writeln!(file, "time").expect("Failed to write CSV header");
    
    // Run N signing requests (10% warmup + num_requests recorded)
    let warmup_requests = (num_requests as f64 * 0.1) as usize;
    let total_requests = warmup_requests + num_requests;
    let mut total_time = 0.0;
    let progress_interval = if total_requests >= 10000 { 10000 } else { 100 };
    
    println!("Warmup: {} requests", warmup_requests);
    println!("Recording: {} requests", num_requests);
    if let Some(idx) = fixed_key_index {
        println!("Using fixed key index: {}\n", idx);
    } else {
        println!("Using random key indices\n");
    }
    
    for i in 0..total_requests {
        // Random or fixed key index
        let key_idx = if let Some(idx) = fixed_key_index {
            idx % index_size  // Ensure index is within bounds
        } else {
            rng.gen_range(0..index_size)
        };
        
        // Generate 32-byte message
        let mut message = [0u8; 32];
        rng.fill(&mut message);
        
        // Measure signing time
        let start = Instant::now();
        let _signature = signing_keys[key_idx].sign(&message);
        let duration = start.elapsed();
        
        let time_us = duration.as_secs_f64() * 1_000_000.0;
        
        // Only record after warmup
        if i >= warmup_requests {
            total_time += time_us;
            writeln!(file, "{:.6}", time_us).expect("Failed to write CSV row");
        }
        
        if (i + 1) % progress_interval == 0 {
            println!("Completed {} requests", i + 1);
        }
    }
    
    let avg_time = total_time / num_requests as f64;
    println!("\n=== Signing Metrics ===");
    println!("Total requests: {}", num_requests);
    println!("Average signing time: {:.3} µs", avg_time);
    println!("Average signing time: {:.6} ms", avg_time / 1000.0);
    println!("Throughput: {:.0} signatures/sec", 1_000_000.0 / avg_time);
    println!("\nResults saved to {}", filename);
}

fn generate_permutation(domain: &str, epoch_id: &str, n: usize) {
    use rand::seq::SliceRandom;
    
    let epoch_folder = format!("NAEF/{}/{}", domain.replace('.', "_"), epoch_id);
    if !std::path::Path::new(&epoch_folder).exists() {
        println!("Error: {} not found. Run 'kda epr {}' first.", epoch_folder, domain);
        return;
    }

    let mut numbers: Vec<usize> = (1..=n).collect();
    let mut rng = rand::thread_rng();
    numbers.shuffle(&mut rng);
    
    let permutation = numbers.iter()
        .map(|num| num.to_string())
        .collect::<Vec<String>>()
        .join(",");
    
    let filepath = format!("{}/permute.txt", epoch_folder);
    std::fs::write(&filepath, &permutation).expect("Failed to write permutation file");
    
    println!("Permutation: {}", permutation);
    println!("Saved to {}", filepath);
}

fn run_naef_metrics(iterations: usize) {
    use std::time::Instant;
    use std::fs::File;
    use std::io::Write;
    use std::process::Command;
    
    println!("Running NAEF metrics for {} iterations...", iterations);
    
    let mut kda_file = File::create("kda.csv").expect("Failed to create kda.csv");
    writeln!(kda_file, "iteration,keygen_ms,commit_ms,permute_ms,fragment_ms").expect("Failed to write header");
    
    let mut vda_file = File::create("vda.csv").expect("Failed to create vda.csv");
    writeln!(vda_file, "iteration,decrypt_ms,reconstruct_ms,verifycommit_ms,publish_ms").expect("Failed to write header");
    
    for i in 1..=iterations {
        println!("\n=== Iteration {}/{} ===", i, iterations);
        
        // KDA: keygen
        let start = Instant::now();
        generate_keypair();
        let keygen_ms = start.elapsed().as_secs_f64() * 1000.0;
        
        // KDA: commit
        let start = Instant::now();
        generate_commitment();
        let commit_ms = start.elapsed().as_secs_f64() * 1000.0;
        
        // KDA: permute
        let start = Instant::now();
        generate_permutation("metrics", "0", 5);
        let permute_ms = start.elapsed().as_secs_f64() * 1000.0;
        
        // KDA: fragment
        let start = Instant::now();
        send_fragment("metrics", "0");
        let fragment_ms = start.elapsed().as_secs_f64() * 1000.0;
        
        writeln!(kda_file, "{},{:.3},{:.3},{:.3},{:.3}", i, keygen_ms, commit_ms, permute_ms, fragment_ms)
            .expect("Failed to write kda.csv");
        
        // VDA: decrypt
        let start = Instant::now();
        let _ = Command::new("./vda").args(&["decrypt", "--text"]).output();
        let decrypt_ms = start.elapsed().as_secs_f64() * 1000.0;
        
        // VDA: reconstruct
        let start = Instant::now();
        let _ = Command::new("./vda").arg("reconstruct").output();
        let reconstruct_ms = start.elapsed().as_secs_f64() * 1000.0;
        
        // VDA: verifycommit
        let start = Instant::now();
        let _ = Command::new("./vda").arg("VerifyCommit").output();
        let verifycommit_ms = start.elapsed().as_secs_f64() * 1000.0;
        
        // VDA: publish
        let start = Instant::now();
        let _ = Command::new("./vda").arg("publish").output();
        let publish_ms = start.elapsed().as_secs_f64() * 1000.0;
        
        writeln!(vda_file, "{},{:.3},{:.3},{:.3},{:.3}", i, decrypt_ms, reconstruct_ms, verifycommit_ms, publish_ms)
            .expect("Failed to write vda.csv");
        
        println!("Iteration {} complete", i);
    }
    
    println!("\n=== Metrics Complete ===");
    println!("KDA metrics saved to kda.csv");
    println!("VDA metrics saved to vda.csv");
}

fn show_kda_storage() {
    println!("=== KDA Storage Requirements ===");
    println!();
    
    let mut total_size = 0u64;
    
    // Check private_key.pem
    if let Ok(metadata) = std::fs::metadata("private_key.pem") {
        let size = metadata.len();
        total_size += size;
        println!("private_key.pem:        {:>8} bytes  (RSA 4096-bit private key)", size);
    } else {
        println!("private_key.pem:        Not found");
    }
    
    // Check public_key.pem
    if let Ok(metadata) = std::fs::metadata("public_key.pem") {
        let size = metadata.len();
        total_size += size;
        println!("public_key.pem:         {:>8} bytes  (RSA 4096-bit public key)", size);
    } else {
        println!("public_key.pem:         Not found");
    }
    
    // Check .rust_keypair.bin
    if let Ok(metadata) = std::fs::metadata(".rust_keypair.bin") {
        let size = metadata.len();
        total_size += size;
        println!(".rust_keypair.bin:      {:>8} bytes  (Kyber post-quantum keypair)", size);
    } else {
        println!(".rust_keypair.bin:      Not found");
    }
    
    // Check commitment.txt
    if let Ok(metadata) = std::fs::metadata("commitment.txt") {
        let size = metadata.len();
        total_size += size;
        println!("commitment.txt:         {:>8} bytes  (Disclosure commitment)", size);
    } else {
        println!("commitment.txt:         Not found");
    }
    
    // Check permute.txt
    if let Ok(metadata) = std::fs::metadata("permute.txt") {
        let size = metadata.len();
        total_size += size;
        println!("permute.txt:            {:>8} bytes  (Fragment permutation order)", size);
    } else {
        println!("permute.txt:            Not found");
    }
    
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
    
    println!();
    println!("Total KDA Storage:      {:>8} bytes  ({:.2} KB)", total_size, total_size as f64 / 1024.0);
    println!();
    
    // Breakdown by category
    println!("=== Storage Breakdown ===");
    println!();
    
    let key_size = std::fs::metadata("private_key.pem").map(|m| m.len()).unwrap_or(0)
        + std::fs::metadata("public_key.pem").map(|m| m.len()).unwrap_or(0)
        + std::fs::metadata(".rust_keypair.bin").map(|m| m.len()).unwrap_or(0);
    
    let commitment_size = std::fs::metadata("commitment.txt").map(|m| m.len()).unwrap_or(0);
    
    let fragment_size = fragment_total;
    
    let metadata_size = std::fs::metadata("permute.txt").map(|m| m.len()).unwrap_or(0);
    
    println!("Cryptographic Keys:     {:>8} bytes  ({:.1}%)", key_size, (key_size as f64 / total_size as f64) * 100.0);
    println!("Commitment:             {:>8} bytes  ({:.1}%)", commitment_size, (commitment_size as f64 / total_size as f64) * 100.0);
    println!("Key Fragments:          {:>8} bytes  ({:.1}%)", fragment_size, (fragment_size as f64 / total_size as f64) * 100.0);
    println!("Metadata:               {:>8} bytes  ({:.1}%)", metadata_size, (metadata_size as f64 / total_size as f64) * 100.0);
}

struct TebsBeacon {
    epoch: String,
    epoch_time: String,
    timestamp: String,
    beacon: String,
    proof: String,
}

fn read_tebs_beacon() -> TebsBeacon {
    let mut tb = TebsBeacon {
        epoch: String::new(),
        epoch_time: String::new(),
        timestamp: String::new(),
        beacon: String::new(),
        proof: String::new(),
    };
    if let Ok(content) = std::fs::read_to_string("tebs_beacon.txt") {
        for line in content.lines() {
            if let Some(v) = line.strip_prefix("epoch:") { tb.epoch = v.trim().to_string(); }
            else if let Some(v) = line.strip_prefix("epoch_time:") { tb.epoch_time = v.trim().to_string(); }
            else if let Some(v) = line.strip_prefix("timestamp:") { tb.timestamp = v.trim().to_string(); }
            else if let Some(v) = line.strip_prefix("beacon:") { tb.beacon = v.trim().to_string(); }
            else if let Some(v) = line.strip_prefix("proof:") { tb.proof = v.trim().to_string(); }
        }
    }
    tb
}

fn tebs_lookup(epoch_time: Option<u64>) {
    use std::process::Command;
    let output = if let Some(t) = epoch_time {
        Command::new("./tebs")
            .args(&["lookup", &t.to_string()])
            .output()
            .expect("Failed to run tebs lookup. Is the tebs binary available?")
    } else {
        // Read last line from tebs_beacon.log for latest value
        let content = match std::fs::read_to_string("tebs_beacon.log") {
            Ok(c) => c,
            Err(_) => {
                println!("Error: tebs_beacon.log not found. Is TEBS running?");
                return;
            }
        };
        let last_line = match content.lines().rev().find(|l| !l.is_empty()) {
            Some(l) => l.to_string(),
            None => {
                println!("Error: tebs_beacon.log is empty.");
                return;
            }
        };

        let mut epoch = String::new();
        let mut et = String::new();
        let mut timestamp = String::new();
        let mut beacon = String::new();
        let mut proof = String::new();

        for part in last_line.split_whitespace() {
            if let Some(v) = part.strip_prefix("epoch:") { epoch = v.to_string(); }
            else if let Some(v) = part.strip_prefix("epoch_time:") { et = v.to_string(); }
            else if let Some(v) = part.strip_prefix("timestamp:") { timestamp = v.to_string(); }
            else if let Some(v) = part.strip_prefix("beacon:") { beacon = v.to_string(); }
            else if let Some(v) = part.strip_prefix("proof:") { proof = v.to_string(); }
        }

        let content = format!(
            "epoch:{}\nepoch_time:{}\ntimestamp:{}\nbeacon:{}\nproof:{}\n",
            epoch, et, timestamp, beacon, proof
        );

        std::fs::write("tebs_beacon.txt", &content).expect("Failed to write tebs_beacon.txt");
        println!("Latest TEBS beacon:");
        println!("  epoch:      {}", epoch);
        println!("  epoch_time: {}", et);
        println!("  timestamp:  {}", timestamp);
        println!("  beacon:     {}", beacon);
        println!("  proof:      {}", proof);
        println!("Saved to tebs_beacon.txt");
        return;
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);

    // Parse the lookup output for beacon fields
    let mut epoch = String::new();
    let mut et = String::new();
    let mut timestamp = String::new();
    let mut beacon = String::new();
    let mut proof = String::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("epoch:") { epoch = trimmed.trim_start_matches("epoch:").trim().to_string(); }
        else if trimmed.starts_with("epoch_time:") { et = trimmed.trim_start_matches("epoch_time:").trim().to_string(); }
        else if trimmed.starts_with("timestamp:") { timestamp = trimmed.trim_start_matches("timestamp:").trim().to_string(); }
        else if trimmed.starts_with("beacon:") { beacon = trimmed.trim_start_matches("beacon:").trim().to_string(); }
        else if trimmed.starts_with("proof:") { proof = trimmed.trim_start_matches("proof:").trim().to_string(); }
    }

    if beacon.is_empty() {
        println!("No beacon found for epoch_time {:?}", epoch_time);
        return;
    }

    let content = format!(
        "epoch:{}\nepoch_time:{}\ntimestamp:{}\nbeacon:{}\nproof:{}\n",
        epoch, et, timestamp, beacon, proof
    );

    std::fs::write("tebs_beacon.txt", &content).expect("Failed to write tebs_beacon.txt");
    println!("Saved to tebs_beacon.txt");
}

fn generate_epr(domain: &str) {
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

    let config = match read_domain_config(domain) {
        Some(c) => c,
        None => {
            println!("Error: Domain '{}' not found in NAEF/init.json. Run 'kda init' first.", domain);
            return;
        }
    };

    let interval: u64 = config.epoch_interval.parse().unwrap_or(6);
    let domain_folder = format!("NAEF/{}", domain.replace('.', "_"));
    std::fs::create_dir_all(&domain_folder).expect("Failed to create domain folder");

    // Determine next epoch_id from existing epoch folders
    let mut max_epoch: u64 = 0;
    if let Ok(entries) = std::fs::read_dir(&domain_folder) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(val) = name.parse::<u64>() {
                        if val > max_epoch { max_epoch = val; }
                    }
                }
            }
        }
    }
    let epoch_id = max_epoch + interval;

    let epoch_folder = format!("{}/{}", domain_folder, epoch_id);
    std::fs::create_dir_all(&epoch_folder).expect("Failed to create epoch folder");

    // Generate RSA 4096-bit key pair for this epoch
    println!("Generating RSA key pair for epoch {}...", epoch_id);
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 4096).expect("Failed to generate private key");
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF).expect("Failed to encode private key");
    let public_pem = public_key.to_public_key_pem(LineEnding::LF).expect("Failed to encode public key");

    std::fs::write(format!("{}/private_key.pem", epoch_folder), private_pem.as_bytes())
        .expect("Failed to write private key");
    std::fs::write(format!("{}/public_key.pem", epoch_folder), public_pem.as_bytes())
        .expect("Failed to write public key");

    // Generate VRF key pair (Ed25519)
    use ed25519_dalek::{SigningKey as VrfSigningKey};
    let mut vrf_secret = [0u8; 32];
    rng.fill(&mut vrf_secret);
    let vrf_sk = VrfSigningKey::from_bytes(&vrf_secret);
    let vrf_pk = vrf_sk.verifying_key();
    std::fs::write(format!("{}/vrf_key.bin", epoch_folder), &vrf_secret)
        .expect("Failed to write VRF private key");
    std::fs::write(format!("{}/vrf_pubkey.hex", epoch_folder), hex::encode(vrf_pk.to_bytes()))
        .expect("Failed to write VRF public key");

    let dkimpk = public_pem.to_string()
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();

    let epr_path = format!("{}/epr.txt", epoch_folder);
    let content = format!(
        "domain: {}\nepoch_id: {}\nselector: {}\ndkimpk: {}\n",
        config.domain, epoch_id, config.selector, dkimpk
    );

    std::fs::write(&epr_path, &content).expect("Failed to write EPR file");

    println!("Epoch Public Registration generated:");
    println!("  domain:   {}", config.domain);
    println!("  epoch_id: {}", epoch_id);
    println!("  selector: {}", config.selector);
    println!("  dkimpk:   {}...{}", &dkimpk[..20], &dkimpk[dkimpk.len()-20..]);
    println!("Saved to {}", epr_path);
}

struct DomainConfig {
    domain: String,
    epoch_interval: String,
    selector: String,
    num_fragments: usize,
    fah: usize,
}

fn read_domain_config(domain: &str) -> Option<DomainConfig> {
    let content = std::fs::read_to_string("NAEF/init.json").ok()?;
    for entry in content.split('{').skip(1) {
        let mut d = String::new();
        let mut ei = String::new();
        let mut sel = String::new();
        let mut nf = String::from("5");
        let mut fah = String::from("5");
        for part in entry.split(',') {
            let clean = part.replace('}', "").replace(']', "").replace('\n', "");
            let clean = clean.trim();
            if let Some((key, val)) = clean.split_once(':') {
                let key = key.trim().trim_matches('"');
                let val = val.trim().trim_matches('"');
                match key {
                    "domain" => d = val.to_string(),
                    "epoch_interval" => ei = val.to_string(),
                    "selector" => sel = val.to_string(),
                    "num_fragments" => nf = val.to_string(),
                    "fah" => fah = val.to_string(),
                    _ => {}
                }
            }
        }
        if d == domain {
            return Some(DomainConfig {
                domain: d,
                epoch_interval: ei,
                selector: sel,
                num_fragments: nf.parse().unwrap_or(5),
                fah: fah.parse().unwrap_or(5),
            });
        }
    }
    None
}

fn generate_init(domain: &str, epoch_interval: &str, selector: &str, num_fragments: usize, fah: usize) {
    std::fs::create_dir_all("NAEF").expect("Failed to create NAEF folder");

    let init_path = "NAEF/init.json";
    let mut entries: Vec<String> = Vec::new();

    if let Ok(content) = std::fs::read_to_string(init_path) {
        for entry in content.split('{').skip(1) {
            let mut d = String::new();
            let mut ei = String::new();
            let mut sel = String::new();
            let mut nf = String::new();
            let mut f = String::new();
            for part in entry.split(',') {
                let clean = part.replace('}', "").replace(']', "").replace('\n', "");
                let clean = clean.trim();
                if let Some((key, val)) = clean.split_once(':') {
                    let key = key.trim().trim_matches('"');
                    let val = val.trim().trim_matches('"');
                    match key {
                        "domain" => d = val.to_string(),
                        "epoch_interval" => ei = val.to_string(),
                        "selector" => sel = val.to_string(),
                        "num_fragments" => nf = val.to_string(),
                        "fah" => f = val.to_string(),
                        _ => {}
                    }
                }
            }
            if !d.is_empty() && d != domain {
                if nf.is_empty() { nf = "5".to_string(); }
                if f.is_empty() { f = "5".to_string(); }
                entries.push(format!(
                    "  {{\"domain\":\"{}\",\"epoch_interval\":\"{}\",\"selector\":\"{}\",\"num_fragments\":\"{}\",\"fah\":\"{}\"}}",
                    d, ei, sel, nf, f
                ));
            }
        }
    }

    entries.push(format!(
        "  {{\"domain\":\"{}\",\"epoch_interval\":\"{}\",\"selector\":\"{}\",\"num_fragments\":\"{}\",\"fah\":\"{}\"}}",
        domain, epoch_interval, selector, num_fragments, fah
    ));

    let json = format!("[\n{}\n]", entries.join(",\n"));
    std::fs::write(init_path, &json).expect("Failed to write init.json");

    println!("Domain initialized:");
    println!("  domain:         {}", domain);
    println!("  epoch_interval: {}s", epoch_interval);
    println!("  selector:       {}", selector);
    println!("  num_fragments:  {}", num_fragments);
    println!("  fah:            {}", fah);
    println!("Saved to {}", init_path);
}

fn generate_eka(domain: &str, epoch_id: &str) {
    let epoch_folder = format!("NAEF/{}/{}", domain.replace('.', "_"), epoch_id);

    let private_pem = match std::fs::read_to_string(format!("{}/private_key.pem", epoch_folder)) {
        Ok(key) => key,
        Err(_) => {
            println!("Error: private_key.pem not found in {}. Run 'kda epr {}' first.", epoch_folder, domain);
            return;
        }
    };

    let public_pem = match std::fs::read_to_string(format!("{}/public_key.pem", epoch_folder)) {
        Ok(key) => key,
        Err(_) => {
            println!("Error: public_key.pem not found in {}.", epoch_folder);
            return;
        }
    };

    let eka_path = format!("{}/eka.txt", epoch_folder);
    let content = format!(
        "domain: {}\nepoch_id: {}\nprivate_key: {}\npublic_key: {}\n",
        domain, epoch_id, private_pem.trim(), public_pem.trim()
    );
    std::fs::write(&eka_path, &content).expect("Failed to write EKA file");

    // Generate dkim signing key file for dsmtp
    let dsmtp_folder = format!("NAEF/dsmtp/{}", domain.replace('.', "_"));
    std::fs::create_dir_all(&dsmtp_folder).expect("Failed to create dsmtp folder");
    let dkim_path = format!("{}/{}_dkim.txt", dsmtp_folder, domain.replace('.', "_"));
    let dkim_selector = format!("naef-{}", epoch_id);

    // Extract base64 content from PEM keys
    let private_key_b64 = private_pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let public_key_b64 = public_pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();

    let entry = format!(
        "[epoch:{}]\ndomain: {}\nepoch_id: {}\nselector: {}\nprivate_key: {}\npublic_key: {}\n\n",
        epoch_id, domain, epoch_id, dkim_selector, private_key_b64, public_key_b64
    );
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&dkim_path)
        .expect("Failed to open dkim file");
    file.write_all(entry.as_bytes()).expect("Failed to write dkim entry");
    println!("DKIM signing key appended to {}", dkim_path);
    println!("  selector: {}", dkim_selector);

    println!("Epoch Key Activation generated:");
    println!("  domain:   {}", domain);
    println!("  epoch_id: {}", epoch_id);
    println!("Saved to {}", eka_path);
}

fn generate_kdr(domain: &str, epoch_id: &str) {
    use std::time::{SystemTime, UNIX_EPOCH};
    use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
    use rsa::pkcs8::DecodePrivateKey;

    let epoch_folder = format!("NAEF/{}/{}", domain.replace('.', "_"), epoch_id);

    let private_pem = match std::fs::read_to_string(format!("{}/private_key.pem", epoch_folder)) {
        Ok(key) => key,
        Err(_) => {
            println!("Error: private_key.pem not found in {}. Run 'kda epr {}' first.", epoch_folder, domain);
            return;
        }
    };

    let public_pem = match std::fs::read_to_string(format!("{}/public_key.pem", epoch_folder)) {
        Ok(key) => key,
        Err(_) => {
            println!("Error: public_key.pem not found in {}.", epoch_folder);
            return;
        }
    };

    // Generate commitment: random text -> hash + encrypt
    let mut rng = rand::thread_rng();
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let random_text: String = (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    let mut hasher = Sha3_256::new();
    hasher.update(random_text.as_bytes());
    let hash = hasher.finalize();
    let hash_hex = hex::encode(hash);

    let private_key = match RsaPrivateKey::from_pkcs8_pem(&private_pem) {
        Ok(key) => key,
        Err(e) => {
            println!("Error parsing private key: {}", e);
            return;
        }
    };
    let public_key = RsaPublicKey::from(&private_key);

    let encrypted_bytes = match public_key.encrypt(&mut rng, Pkcs1v15Encrypt, random_text.as_bytes()) {
        Ok(enc) => enc,
        Err(e) => {
            println!("Error encrypting: {}", e);
            return;
        }
    };
    let encrypted_hex = hex::encode(encrypted_bytes);

    // Save commitment to epoch folder
    let commit_content = format!(
        "Random Text: {}\nSHA3-256 Hash: {}\nEncrypted Text: {}\n",
        random_text, hash_hex, encrypted_hex
    );
    std::fs::write(format!("{}/commitment.txt", epoch_folder), &commit_content)
        .expect("Failed to write commitment.txt");

    let dkimpk = public_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let kdr_path = format!("{}/kdr.txt", epoch_folder);
    let content = format!(
        "domain: {}\nepoch_id: {}\npublic_key: {}\nhash_commit: {}\nenc_commit: {}\ntimestamp_utc: {}\n",
        domain, epoch_id, dkimpk, hash_hex, encrypted_hex, timestamp
    );

    std::fs::write(&kdr_path, &content).expect("Failed to write KDR file");

    println!("Key Disclosure Request generated:");
    println!("  domain:      {}", domain);
    println!("  epoch_id:    {}", epoch_id);
    println!("  hash_commit: {}", hash_hex);
    println!("  timestamp:   {}", timestamp);
    println!("Saved to {}", kdr_path);
}

fn generate_dpr(domain: &str, epoch_id: &str) {
    let config = match read_domain_config(domain) {
        Some(c) => c,
        None => {
            println!("Error: Domain '{}' not found in NAEF/init.json.", domain);
            return;
        }
    };

    let epoch_folder = format!("NAEF/{}/{}", domain.replace('.', "_"), epoch_id);
    let num_fragments = config.num_fragments;

    // Check all fragments are done
    let mut processed = 0;
    for i in 1..=num_fragments {
        if std::path::Path::new(&format!("{}/fdr_{}.txt", epoch_folder, i)).exists() {
            processed += 1;
        }
    }
    if processed < num_fragments {
        println!("Error: Only {}/{} fragments created. Complete all fragments first.", processed, num_fragments);
        return;
    }

    // Read the last ebr (ebr_<num_fragments>)
    let last_ebr = read_ebr_file(&epoch_folder, num_fragments);
    if last_ebr.beacon.is_empty() {
        println!("Error: ebr_{}.txt not found in {}.", num_fragments, epoch_folder);
        return;
    }

    // Read permute
    let permute_path = format!("{}/permute.txt", epoch_folder);
    let permutation = match std::fs::read_to_string(&permute_path) {
        Ok(p) => p.trim().to_string(),
        Err(_) => {
            println!("Error: permute.txt not found in {}.", epoch_folder);
            return;
        }
    };

    // Compute VRF for last beacon
    use ed25519_dalek::{SigningKey as VrfSigningKey, Signer as VrfSigner};
    use sha2::{Sha256, Digest as Sha2Digest};
    let vrf_key_path = format!("{}/vrf_key.bin", epoch_folder);
    let vrf_secret = std::fs::read(&vrf_key_path)
        .expect("Failed to read vrf_key.bin");
    let mut vrf_bytes = [0u8; 32];
    vrf_bytes.copy_from_slice(&vrf_secret);
    let vrf_sk = VrfSigningKey::from_bytes(&vrf_bytes);
    let vrf_sig = vrf_sk.sign(last_ebr.beacon.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(vrf_sig.to_bytes());
    let vrf_output_hex = hex::encode(hasher.finalize());
    let vrf_proof_hex = hex::encode(vrf_sig.to_bytes());

    let dpr_path = format!("{}/dpr.txt", epoch_folder);
    let content = format!(
        "domain: {}\nepoch_id: {}\npermutation: {}\nvrf_output: {}\nvrf_proof: {}\ntebs_epoch: {}\ntebs_epoch_time: {}\ntebs_timestamp: {}\ntebs_beacon: {}\ntebs_proof: {}\n",
        domain, epoch_id, permutation,
        vrf_output_hex, vrf_proof_hex,
        last_ebr.epoch, last_ebr.epoch_time, last_ebr.timestamp, last_ebr.beacon, last_ebr.proof
    );

    std::fs::write(&dpr_path, &content).expect("Failed to write DPR file");

    println!("Disclosure Publication Request generated:");
    println!("  domain:      {}", domain);
    println!("  epoch_id:    {}", epoch_id);
    println!("  permutation: {}", permutation);
    println!("  tebs_beacon: {}", &last_ebr.beacon[..16]);
    println!("Saved to {}", dpr_path);
}
