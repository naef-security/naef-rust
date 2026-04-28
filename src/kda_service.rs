use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;

const INIT_PATH: &str = "NAEF/init.json";
const METRICS_DIR: &str = "NAEF/metrics";

struct DomainConfig {
    domain: String,
    epoch_interval: u64,
    num_fragments: usize,
    fah: usize,
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

fn write_metric(domain: &str, epoch_id: &str, operation: &str, duration_ms: f64, num_fragments: usize, fah: usize) {
    std::fs::create_dir_all(METRICS_DIR).ok();
    let path = format!("{}/kda_metrics.csv", METRICS_DIR);
    let needs_header = !std::path::Path::new(&path).exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("Failed to open metrics file");
    if needs_header {
        writeln!(file, "timestamp,domain,epoch_id,operation,duration_ms,num_fragments,fah").ok();
    }
    writeln!(file, "{},{},{},{},{:.3},{},{}", timestamp(), domain, epoch_id, operation, duration_ms, num_fragments, fah).ok();
}

fn write_epoch_metric(domain: &str, epoch_id: &str, epr_ms: f64, eka_ms: f64, kdr_ms: f64, fragment_total_ms: f64, dpr_ms: f64, total_ms: f64, num_fragments: usize, fah: usize) {
    std::fs::create_dir_all(METRICS_DIR).ok();
    let path = format!("{}/kda_epoch_metrics.csv", METRICS_DIR);
    let needs_header = !std::path::Path::new(&path).exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("Failed to open epoch metrics file");
    if needs_header {
        writeln!(file, "timestamp,domain,epoch_id,epr_ms,eka_ms,kdr_ms,fragment_total_ms,dpr_ms,epoch_total_ms,num_fragments,fah").ok();
    }
    writeln!(file, "{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{}", 
        timestamp(), domain, epoch_id, epr_ms, eka_ms, kdr_ms, fragment_total_ms, dpr_ms, total_ms, num_fragments, fah).ok();
}

fn read_all_domains() -> Vec<DomainConfig> {
    let content = match std::fs::read_to_string(INIT_PATH) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut domains = Vec::new();
    for entry in content.split('{').skip(1) {
        let mut d = String::new();
        let mut ei = String::new();
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
                    "num_fragments" => nf = val.to_string(),
                    "fah" => fah = val.to_string(),
                    _ => {}
                }
            }
        }
        if !d.is_empty() {
            domains.push(DomainConfig {
                domain: d,
                epoch_interval: ei.parse().unwrap_or(30),
                num_fragments: nf.parse().unwrap_or(5),
                fah: fah.parse().unwrap_or(5),
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

fn count_fdr_files(epoch_folder: &str, num_fragments: usize) -> usize {
    let mut count = 0;
    for i in 1..=num_fragments {
        if file_exists(&format!("{}/fdr_{}.txt", epoch_folder, i)) {
            count += 1;
        }
    }
    count
}

fn is_epoch_disclosed(epoch_folder: &str) -> bool {
    file_exists(&format!("{}/dpr.txt", epoch_folder))
}

fn run_kda(args: &[&str]) -> String {
    let output = Command::new("./kda")
        .args(args)
        .output()
        .expect("Failed to run kda");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !stderr.is_empty() {
        eprint!("{}", stderr);
    }
    stdout
}

fn run_kda_timed(args: &[&str]) -> (String, f64) {
    let start = Instant::now();
    let out = run_kda(args);
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    (out, ms)
}

fn ensure_fah_epochs(domain: &str, fah: usize, num_fragments: usize) {
    let epochs = get_all_epochs(domain);
    let mut undisclosed_keyed = 0;
    let mut disclosed_count = 0;
    let total_epochs = epochs.len();
    for eid in &epochs {
        let ef = format!("NAEF/{}/{}", domain.replace('.', "_"), eid);
        let has_eka = file_exists(&format!("{}/eka.txt", ef));
        let has_dpr = is_epoch_disclosed(&ef);
        if has_eka && !has_dpr { undisclosed_keyed += 1; }
        if has_dpr { disclosed_count += 1; }
    }

    log_domain(domain, &format!(
        "FAH check: total_epochs={}, disclosed={}, undisclosed_keyed={}, fah={}",
        total_epochs, disclosed_count, undisclosed_keyed, fah));

    let needed = if fah > undisclosed_keyed { fah - undisclosed_keyed } else { 0 };

    if needed > 0 {
        log_domain(domain, &format!("FAH: Need {} more epoch(s) to maintain horizon of {}", needed, fah));

        for i in 0..needed {
            log_domain(domain, &format!("FAH: Creating future epoch {}/{}...", i + 1, needed));
            let (out, epr_ms) = run_kda_timed(&["epr", domain]);
            print!("{}", out);

            let new_epochs = get_all_epochs(domain);
            if let Some(&latest) = new_epochs.last() {
                let latest_str = latest.to_string();
                let ef = format!("NAEF/{}/{}", domain.replace('.', "_"), latest);
                if !file_exists(&format!("{}/eka.txt", ef)) {
                    log(domain, &latest_str, "FAH: Running EKA for future epoch...");
                    let (out, eka_ms) = run_kda_timed(&["eka", domain, &latest_str]);
                    print!("{}", out);
                    write_metric(domain, &latest_str, "fah_epr", epr_ms, num_fragments, fah);
                    write_metric(domain, &latest_str, "fah_eka", eka_ms, num_fragments, fah);
                }
                log(domain, &latest_str, "FAH: Future epoch created and keyed.");
            }
        }

        let final_epochs = get_all_epochs(domain);
        let mut final_count = 0;
        for eid in &final_epochs {
            let ef = format!("NAEF/{}/{}", domain.replace('.', "_"), eid);
            if file_exists(&format!("{}/eka.txt", ef)) && !is_epoch_disclosed(&ef) {
                final_count += 1;
            }
        }
        log_domain(domain, &format!("FAH: {} future epochs now ready for dsmtp", final_count));
    } else {
        log_domain(domain, &format!("FAH: OK ({} undisclosed keyed, fah={})", undisclosed_keyed, fah));
    }
}

fn get_oldest_undisclosed_epoch(domain: &str) -> Option<u64> {
    let epochs = get_all_epochs(domain);
    for eid in &epochs {
        let ef = format!("NAEF/{}/{}", domain.replace('.', "_"), eid);
        if !is_epoch_disclosed(&ef) {
            return Some(*eid);
        }
    }
    None
}

fn run_domain(domain: String, epoch_interval: u64, num_fragments: usize, fah: usize, running: Arc<AtomicBool>) {
    let fragment_interval = epoch_interval / num_fragments as u64;

    log_domain(&domain, &format!(
        "Thread started (epoch_interval={}s, num_fragments={}, fragment_interval={}s, fah={})",
        epoch_interval, num_fragments, fragment_interval, fah));

    ensure_fah_epochs(&domain, fah, num_fragments);

    while running.load(Ordering::SeqCst) {
        let epoch_id = match get_oldest_undisclosed_epoch(&domain) {
            Some(eid) => eid,
            None => {
                log_domain(&domain, "No undisclosed epochs. Creating new epoch...");
                let out = run_kda(&["epr", &domain]);
                print!("  {}", out);
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };

        let epoch_id_str = epoch_id.to_string();
        let epoch_folder = format!("NAEF/{}/{}", domain.replace('.', "_"), epoch_id);
        let epoch_start = Instant::now();
        let mut eka_ms = 0.0;
        let mut kdr_ms = 0.0;
        let mut fragment_total_ms = 0.0;
        let mut dpr_ms = 0.0;

        // EKA
        if !file_exists(&format!("{}/eka.txt", epoch_folder)) {
            log(&domain, &epoch_id_str, "Running Epoch Key Activation...");
            let (out, ms) = run_kda_timed(&["eka", &domain, &epoch_id_str]);
            print!("  {}", out);
            eka_ms = ms;
            write_metric(&domain, &epoch_id_str, "eka", ms, num_fragments, fah);
            continue;
        }

        // KDR
        if !file_exists(&format!("{}/kdr.txt", epoch_folder)) {
            log(&domain, &epoch_id_str, "Running Key Disclosure Request...");
            let (out, ms) = run_kda_timed(&["kdr", &domain, &epoch_id_str]);
            print!("  {}", out);
            kdr_ms = ms;
            write_metric(&domain, &epoch_id_str, "kdr", ms, num_fragments, fah);
            continue;
        }

        // Fragments
        let fdr_count = count_fdr_files(&epoch_folder, num_fragments);
        if fdr_count < num_fragments {
            log(&domain, &epoch_id_str,
                &format!("Fragment {}/{} - Running fragment command...", fdr_count + 1, num_fragments));
            let (out, ms) = run_kda_timed(&["fragment", &domain, &epoch_id_str]);
            print!("  {}", out);
            write_metric(&domain, &epoch_id_str, &format!("fragment_{}", fdr_count + 1), ms, num_fragments, fah);

            let new_count = count_fdr_files(&epoch_folder, num_fragments);
            if new_count < num_fragments {
                log(&domain, &epoch_id_str,
                    &format!("Waiting {}s before next fragment...", fragment_interval));
                for _ in 0..fragment_interval {
                    if !running.load(Ordering::SeqCst) { return; }
                    thread::sleep(Duration::from_secs(1));
                }
            } else {
                log(&domain, &epoch_id_str, "All fragments created.");
            }
            continue;
        }

        // DPR
        if !file_exists(&format!("{}/dpr.txt", epoch_folder)) {
            log(&domain, &epoch_id_str, "Running Disclosure Publication Request...");
            let (out, ms) = run_kda_timed(&["dpr", &domain, &epoch_id_str]);
            print!("  {}", out);
            dpr_ms = ms;
            write_metric(&domain, &epoch_id_str, "dpr", ms, num_fragments, fah);

            let epoch_total_ms = epoch_start.elapsed().as_secs_f64() * 1000.0;
            write_metric(&domain, &epoch_id_str, "epoch_total", epoch_total_ms, num_fragments, fah);

            log(&domain, &epoch_id_str, &format!(
                "Epoch disclosure COMPLETE (dpr={:.1}ms, total={:.1}ms)", dpr_ms, epoch_total_ms));
            log_domain(&domain, "Maintaining Forward Attribution Horizon...");
            ensure_fah_epochs(&domain, fah, num_fragments);
            println!();
            continue;
        }

        ensure_fah_epochs(&domain, fah, num_fragments);
        thread::sleep(Duration::from_secs(1));
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

    log_global("=== KDA Service Started (with metrics) ===");
    log_global(&format!("Config file: {}", INIT_PATH));
    log_global(&format!("Metrics dir: {}", METRICS_DIR));
    log_global("Press Ctrl+C to stop gracefully.");
    println!();

    let mut handles = Vec::new();
    let mut active_domains: HashSet<String> = HashSet::new();

    loop {
        if !running.load(Ordering::SeqCst) { break; }

        let domains = read_all_domains();

        for config in domains {
            if !active_domains.contains(&config.domain) {
                log_global(&format!(
                    "Spawning thread for domain={} (epoch_interval={}s, num_fragments={}, fah={})",
                    config.domain, config.epoch_interval, config.num_fragments, config.fah));

                active_domains.insert(config.domain.clone());
                let domain = config.domain.clone();
                let ei = config.epoch_interval;
                let nf = config.num_fragments;
                let fah = config.fah;
                let r = running.clone();

                let handle = thread::spawn(move || {
                    run_domain(domain, ei, nf, fah, r);
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
    log_global("=== KDA Service Stopped ===");
}
