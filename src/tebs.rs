use std::time::{SystemTime, UNIX_EPOCH, Instant};
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use std::time::Duration;
use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use sha3::{Digest, Sha3_256};
use rand::Rng;

const DEFAULT_MU: u64 = 30;
const TEBS_KEY_FILE: &str = "tebs_key.bin";
const TEBS_BEACON_LOG: &str = "tebs_beacon.log";
const TEBS_PUBKEY_FILE: &str = "tebs_pubkey.hex";
const TEBS_MU_FILE: &str = "tebs_mu.txt";

fn get_mu() -> u64 {
    std::fs::read_to_string(TEBS_MU_FILE)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(DEFAULT_MU)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("showkey") => {
            let key_type = args.get(2).map(|s| s.as_str()).unwrap_or("public");
            show_key(key_type);
            return;
        }
        Some("verify") => {
            verify_beacon_log();
            return;
        }
        Some("VerifySign") => {
            if args.len() < 5 {
                println!("Usage: tebs VerifySign <beacon_value> <proof> <epoch_time>");
                return;
            }
            let beacon = &args[2];
            let proof = &args[3];
            let epoch_time = args[4].parse::<u64>().unwrap_or_else(|_| {
                println!("Usage: tebs VerifySign <beacon_value> <proof> <epoch_time>");
                std::process::exit(1);
            });
            verify_sign(beacon, proof, epoch_time);
            return;
        }
        Some("lookup") => {
            let t = args.get(2)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or_else(|| {
                    println!("Usage: tebs lookup <time>");
                    std::process::exit(1);
                });
            lookup_epoch(t);
            return;
        }
        Some("help") | Some("--help") => {
            let mu = get_mu();
            println!("Usage: tebs <command>");
            println!();
            println!("Commands:");
            println!("  [mu=N]                               Start beacon service (default μ={}s)", mu);
            println!("  showkey [private|public]              Display TEBS signing key (default: public)");
            println!("  lookup <time>                        Lookup beacon for a given time (e.g. tebs lookup 150)");
            println!("  verify                               Verify all beacon entries in {}", TEBS_BEACON_LOG);
            println!("  VerifySign <beacon> <proof> <epoch>   Verify a beacon signature for epoch (30,60,90...)");
            println!();
            println!("Service parameters:");
            println!("  mu=N  Beacon interval in seconds (default: {})", DEFAULT_MU);
            println!();
            println!("Notes:");
            println!("  - Beacon value B_b = SHA3-256(prev_beacon || random || timestamp)");
            println!("  - Proof τ_b = EdDSA signature over (epoch_time:beacon_value)");
            println!("  - Beacon log appended to {}", TEBS_BEACON_LOG);
            println!("  - μ value saved to {} for use by lookup/verify", TEBS_MU_FILE);
            return;
        }
        _ => {}
    }

    // Parse mu= parameter
    let mut mu = DEFAULT_MU;
    for arg in args.iter().skip(1) {
        if arg.starts_with("mu=") || arg.starts_with("MU=") {
            mu = arg[3..].parse::<u64>().unwrap_or(DEFAULT_MU);
        }
    }

    // Save mu so lookup/verify can use it
    std::fs::write(TEBS_MU_FILE, mu.to_string()).expect("Failed to write mu file");

    println!("=== Trusted Epoch Beacon Service (TEBS) ===");
    println!("Beacon interval μ = {}s", mu);
    println!();

    let signing_key = load_or_generate_key();
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex::encode(verifying_key.to_bytes());

    std::fs::write(TEBS_PUBKEY_FILE, &pubkey_hex).expect("Failed to write pubkey");
    println!("TEBS public key: {}", pubkey_hex);
    println!("Beacon log: {}", TEBS_BEACON_LOG);
    println!();

    let mut epoch: u64 = 1;
    let mut prev_beacon = String::from("0000000000000000000000000000000000000000000000000000000000000000");

    // Resume epoch count from existing log
    if let Ok(content) = std::fs::read_to_string(TEBS_BEACON_LOG) {
        for line in content.lines() {
            if line.is_empty() { continue; }
            let mut e = 0u64;
            let mut b = String::new();
            for part in line.split_whitespace() {
                if let Some(v) = part.strip_prefix("epoch:") { e = v.parse().unwrap_or(0); }
                else if let Some(v) = part.strip_prefix("beacon:") { b = v.to_string(); }
            }
            if e >= epoch {
                epoch = e + 1;
                prev_beacon = b;
            }
        }
        if epoch > 1 {
            println!("Resuming from epoch {}...", epoch);
        }
    }

    println!("Service started. Press Ctrl+C to stop.\n");

    loop {
        let start = Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let epoch_time = epoch * mu;

        let mut rng = rand::thread_rng();
        let mut random_bytes = [0u8; 32];
        rng.fill(&mut random_bytes);

        let mut hasher = Sha3_256::new();
        hasher.update(prev_beacon.as_bytes());
        hasher.update(&random_bytes);
        hasher.update(&timestamp.to_be_bytes());
        let beacon_hash = hasher.finalize();
        let beacon_value = hex::encode(beacon_hash);

        let sign_input = format!("{}:{}", epoch_time, beacon_value);
        let signature = signing_key.sign(sign_input.as_bytes());
        let proof = hex::encode(signature.to_bytes());

        let entry = format!(
            "epoch:{} epoch_time:{} timestamp:{} beacon:{} proof:{}\n",
            epoch, epoch_time, timestamp, beacon_value, proof
        );

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(TEBS_BEACON_LOG)
            .expect("Failed to open beacon log");
        file.write_all(entry.as_bytes()).expect("Failed to write beacon");

        println!("β_{} | epoch_time={} | t={} | B={}", epoch, epoch_time, timestamp, &beacon_value[..16]);

        prev_beacon = beacon_value;
        epoch += 1;

        let elapsed = start.elapsed();
        if elapsed < Duration::from_secs(mu) {
            thread::sleep(Duration::from_secs(mu) - elapsed);
        }
    }
}

fn load_or_generate_key() -> SigningKey {
    if let Ok(data) = std::fs::read(TEBS_KEY_FILE) {
        if data.len() == 32 {
            println!("Loaded TEBS signing key from {}", TEBS_KEY_FILE);
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&data);
            return SigningKey::from_bytes(&bytes);
        }
    }

    println!("Generating new TEBS signing key...");
    let mut rng = rand::thread_rng();
    let mut secret_bytes = [0u8; 32];
    rng.fill(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    std::fs::write(TEBS_KEY_FILE, &secret_bytes).expect("Failed to save TEBS key");
    println!("Saved to {}", TEBS_KEY_FILE);
    signing_key
}

fn show_key(key_type: &str) {
    match key_type {
        "private" => {
            match std::fs::read(TEBS_KEY_FILE) {
                Ok(data) => println!("TEBS private key: {}", hex::encode(&data)),
                Err(_) => println!("No TEBS key found. Start the service first."),
            }
        }
        _ => {
            if let Ok(key) = std::fs::read_to_string(TEBS_PUBKEY_FILE) {
                println!("TEBS public key: {}", key);
            } else if let Ok(data) = std::fs::read(TEBS_KEY_FILE) {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&data);
                let sk = SigningKey::from_bytes(&bytes);
                println!("TEBS public key: {}", hex::encode(sk.verifying_key().to_bytes()));
            } else {
                println!("No TEBS key found. Start the service first.");
            }
        }
    }
}

fn lookup_epoch(t: u64) {
    let mu = get_mu();
    let epoch = if t % mu == 0 { t / mu } else { (t / mu) + 1 };

    println!("Time {} maps to epoch {} (epoch_time={}, μ={})", t, epoch, epoch * mu, mu);

    let content = match std::fs::read_to_string(TEBS_BEACON_LOG) {
        Ok(c) => c,
        Err(_) => {
            println!("Error: {} not found.", TEBS_BEACON_LOG);
            return;
        }
    };

    for line in content.lines() {
        if line.is_empty() { continue; }
        let mut e = String::new();
        let mut epoch_time = String::new();
        let mut timestamp = String::new();
        let mut beacon = String::new();
        let mut proof = String::new();

        for part in line.split_whitespace() {
            if let Some(v) = part.strip_prefix("epoch:") { e = v.to_string(); }
            else if let Some(v) = part.strip_prefix("epoch_time:") { epoch_time = v.to_string(); }
            else if let Some(v) = part.strip_prefix("timestamp:") { timestamp = v.to_string(); }
            else if let Some(v) = part.strip_prefix("beacon:") { beacon = v.to_string(); }
            else if let Some(v) = part.strip_prefix("proof:") { proof = v.to_string(); }
        }

        if e == epoch.to_string() {
            println!("\nepoch:      {}", e);
            println!("epoch_time: {}", epoch_time);
            println!("timestamp:  {}", timestamp);
            println!("beacon:     {}", beacon);
            println!("proof:      {}", proof);
            return;
        }
    }

    println!("Epoch {} not found in beacon log.", epoch);
}

fn verify_sign(beacon_value: &str, proof: &str, epoch_time: u64) {
    let pubkey_hex = match std::fs::read_to_string(TEBS_PUBKEY_FILE) {
        Ok(key) => key.trim().to_string(),
        Err(_) => {
            println!("Error: {} not found. Start the service first.", TEBS_PUBKEY_FILE);
            return;
        }
    };

    let pubkey_bytes = hex::decode(&pubkey_hex).expect("Invalid pubkey hex");
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes.as_slice().try_into().unwrap())
        .expect("Invalid public key");

    use ed25519_dalek::{Signature, Verifier};

    let sign_input = format!("{}:{}", epoch_time, beacon_value);
    let sig_bytes = match hex::decode(proof) {
        Ok(b) => b,
        Err(_) => {
            println!("Error: Invalid proof hex");
            return;
        }
    };
    let signature = Signature::from_bytes(&sig_bytes.as_slice().try_into().unwrap());

    match verifying_key.verify(sign_input.as_bytes(), &signature) {
        Ok(_) => {
            println!("✓ VERIFICATION SUCCESSFUL");
            println!("  epoch_time: {}", epoch_time);
            println!("  beacon:     {}", beacon_value);
        }
        Err(_) => {
            println!("✗ VERIFICATION FAILED");
            println!("  Signature does not match beacon value at epoch_time {}", epoch_time);
        }
    }
}

fn verify_beacon_log() {
    let pubkey_hex = match std::fs::read_to_string(TEBS_PUBKEY_FILE) {
        Ok(key) => key.trim().to_string(),
        Err(_) => {
            println!("Error: {} not found. Start the service first.", TEBS_PUBKEY_FILE);
            return;
        }
    };

    let pubkey_bytes = hex::decode(&pubkey_hex).expect("Invalid pubkey hex");
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes.as_slice().try_into().unwrap())
        .expect("Invalid public key");

    let content = match std::fs::read_to_string(TEBS_BEACON_LOG) {
        Ok(c) => c,
        Err(_) => {
            println!("Error: {} not found.", TEBS_BEACON_LOG);
            return;
        }
    };

    use ed25519_dalek::{Signature, Verifier};

    let mut valid = 0;
    let mut invalid = 0;

    for line in content.lines() {
        if line.is_empty() { continue; }

        let mut epoch = String::new();
        let mut epoch_time = String::new();
        let mut beacon = String::new();
        let mut proof = String::new();

        for part in line.split_whitespace() {
            if let Some(v) = part.strip_prefix("epoch:") { epoch = v.to_string(); }
            else if let Some(v) = part.strip_prefix("epoch_time:") { epoch_time = v.to_string(); }
            else if let Some(v) = part.strip_prefix("beacon:") { beacon = v.to_string(); }
            else if let Some(v) = part.strip_prefix("proof:") { proof = v.to_string(); }
        }

        let sign_input = format!("{}:{}", epoch_time, beacon);
        let sig_bytes = hex::decode(&proof).expect("Invalid proof hex");
        let signature = Signature::from_bytes(&sig_bytes.as_slice().try_into().unwrap());

        match verifying_key.verify(sign_input.as_bytes(), &signature) {
            Ok(_) => {
                valid += 1;
                println!("✓ epoch {} (epoch_time={}) verified", epoch, epoch_time);
            }
            Err(_) => {
                invalid += 1;
                println!("✗ epoch {} (epoch_time={}) FAILED", epoch, epoch_time);
            }
        }
    }

    println!("\n{} valid, {} invalid out of {} entries", valid, invalid, valid + invalid);
}
