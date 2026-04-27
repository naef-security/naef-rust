use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashSet;

const INIT_PATH: &str = "NAEF/init.json";

struct DomainConfig {
    domain: String,
    num_fragments: usize,
}

fn timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn log(domain: &str, epoch: &str, msg: &str) {
    println!("[{}] [{}] epoch={} {}", timestamp(), domain, epoch, msg);
}

fn log_domain(domain: &str, msg: &str) {
    println!("[{}] [{}] {}", timestamp(), domain, msg);
}

fn log_global(msg: &str) {
    println!("[{}] {}", timestamp(), msg);
}

fn read_all_domains() -> Vec<DomainConfig> {
    let content = match std::fs::read_to_string(INIT_PATH) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut domains = Vec::new();
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
        if !d.is_empty() {
            domains.push(DomainConfig {
                domain: d,
                num_fragments: nf.parse().unwrap_or(5),
            });
        }
    }
    domains
}

fn get_all_epochs(domain: &str) -> Vec<u64> {
    let domain_folder = format!("NAEF/{}", domain.replace('.', "_"));
    let mut epochs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&domain_folder) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(val) = name.parse::<u64>() {
                        epochs.push(val);
                    }
                }
            }
        }
    }
    epochs.sort();
    epochs
}

fn file_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

fn count_files(epoch_folder: &str, prefix: &str, num_fragments: usize) -> usize {
    let mut count = 0;
    for i in 1..=num_fragments {
        if file_exists(&format!("{}/{}_{}.txt", epoch_folder, prefix, i)) {
            count += 1;
        }
    }
    count
}

fn run_vda(args: &[&str]) -> String {
    let output = Command::new("./vda")
        .args(args)
        .output()
        .expect("Failed to run vda");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !stderr.is_empty() {
        eprint!("{}", stderr);
    }
    stdout
}

fn run_domain(domain: String, num_fragments: usize, running: Arc<AtomicBool>) {
    log_domain(&domain, &format!("Thread started (num_fragments={})", num_fragments));

    while running.load(Ordering::SeqCst) {
        let epochs = get_all_epochs(&domain);

        if epochs.is_empty() {
            thread::sleep(Duration::from_secs(2));
            continue;
        }

        let mut any_work = false;

        for epoch_id in &epochs {
            if !running.load(Ordering::SeqCst) { break; }

            let epoch_id_str = epoch_id.to_string();
            let epoch_folder = format!("NAEF/{}/{}", domain.replace('.', "_"), epoch_id);

            // Skip verified epochs
            if file_exists(&format!("{}/verified.txt", epoch_folder)) {
                continue;
            }

            let fdr_count = count_files(&epoch_folder, "fdr", num_fragments);
            let decrypt_count = count_files(&epoch_folder, "decrypt", num_fragments);

            // Try to decrypt next fragment
            if decrypt_count < num_fragments {
                let next_seq = decrypt_count + 1;

                if !file_exists(&format!("{}/fdr_{}.txt", epoch_folder, next_seq)) {
                    log(&domain, &epoch_id_str,
                        &format!("Waiting for fdr_{}.txt ({} fdr received, {}/{} decrypted)",
                            next_seq, fdr_count, decrypt_count, num_fragments));
                    continue;
                }

                let can_decrypt = if next_seq < num_fragments {
                    file_exists(&format!("{}/fdr_{}.txt", epoch_folder, next_seq + 1))
                } else {
                    file_exists(&format!("{}/dpr.txt", epoch_folder))
                };

                if can_decrypt {
                    any_work = true;
                    let source = if next_seq < num_fragments {
                        format!("fdr_{}.txt", next_seq + 1)
                    } else {
                        "dpr.txt".to_string()
                    };
                    log(&domain, &epoch_id_str,
                        &format!("Decrypting fragment {}/{} (vrf_output from {})",
                            next_seq, num_fragments, source));
                    let out = run_vda(&["decrypt", &domain, &epoch_id_str]);
                    print!("  {}", out);

                    let new_decrypt = count_files(&epoch_folder, "decrypt", num_fragments);
                    if new_decrypt > decrypt_count {
                        log(&domain, &epoch_id_str,
                            &format!("Fragment {} decrypted successfully ({}/{})",
                                next_seq, new_decrypt, num_fragments));
                    }
                    continue;
                } else {
                    let needed = if next_seq < num_fragments {
                        format!("fdr_{}.txt", next_seq + 1)
                    } else {
                        "dpr.txt".to_string()
                    };
                    log(&domain, &epoch_id_str,
                        &format!("Cannot decrypt fdr_{} - waiting for {} ({}/{} decrypted)",
                            next_seq, needed, decrypt_count, num_fragments));
                    continue;
                }
            }

            // All decrypted → Reconstruct
            if decrypt_count == num_fragments
                && !file_exists(&format!("{}/recon.txt", epoch_folder))
                && file_exists(&format!("{}/dpr.txt", epoch_folder))
            {
                any_work = true;
                log(&domain, &epoch_id_str,
                    &format!("All {}/{} fragments decrypted. Reconstructing private key from dpr.txt permutation...",
                        decrypt_count, num_fragments));
                let out = run_vda(&["reconstruct", &domain, &epoch_id_str]);
                print!("  {}", out);

                if file_exists(&format!("{}/recon.txt", epoch_folder)) {
                    log(&domain, &epoch_id_str, "Private key reconstructed successfully.");
                } else {
                    log(&domain, &epoch_id_str, "ERROR: Reconstruction failed.");
                }
                continue;
            }

            // Reconstructed → VerifyCommit
            if file_exists(&format!("{}/recon.txt", epoch_folder))
                && file_exists(&format!("{}/commitment.txt", epoch_folder))
                && !file_exists(&format!("{}/verified.txt", epoch_folder))
            {
                any_work = true;
                log(&domain, &epoch_id_str, "Running VerifyCommit (recon.txt + commitment.txt)...");
                let out = run_vda(&["VerifyCommit", &domain, &epoch_id_str]);
                print!("  {}", out);

                std::fs::write(
                    format!("{}/verified.txt", epoch_folder),
                    format!("verified_at: {}\n", timestamp())
                ).ok();
                log(&domain, &epoch_id_str, "✓ Epoch verification COMPLETE.");
                println!();
            }
        }

        if any_work {
            thread::sleep(Duration::from_millis(500));
        } else {
            thread::sleep(Duration::from_secs(2));
        }
    }

    log_domain(&domain, "Thread stopped.");
}

fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\n[{}] Received shutdown signal. Stopping all domain threads...", timestamp());
        r.store(false, Ordering::SeqCst);
    }).expect("Failed to set Ctrl+C handler");

    log_global("=== VDA Service Started ===");
    log_global(&format!("Config file: {}", INIT_PATH));
    log_global("Press Ctrl+C to stop gracefully.");
    println!();

    let mut handles = Vec::new();
    let mut active_domains: HashSet<String> = HashSet::new();

    loop {
        if !running.load(Ordering::SeqCst) { break; }

        let domains = read_all_domains();

        for config in domains {
            if !active_domains.contains(&config.domain) {
                log_global(&format!("Spawning thread for domain={} (num_fragments={})",
                    config.domain, config.num_fragments));

                active_domains.insert(config.domain.clone());
                let domain = config.domain.clone();
                let nf = config.num_fragments;
                let r = running.clone();

                let handle = thread::spawn(move || {
                    run_domain(domain, nf, r);
                });
                handles.push(handle);
            }
        }

        for _ in 0..5 {
            if !running.load(Ordering::SeqCst) { break; }
            thread::sleep(Duration::from_secs(1));
        }
    }

    log_global("Waiting for all domain threads to finish...");
    for handle in handles {
        handle.join().ok();
    }
    log_global("=== VDA Service Stopped ===");
}
