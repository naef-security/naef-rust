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

fn main() {
    match dotenv() {
        Ok(path) => println!("Loaded .env from: {:?}", path),
        Err(e) => println!("Warning: Could not load .env: {}", e),
    }
    
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: cargo run -- [ShowKey|decrypt]");
        println!("  decrypt --email   : Reconstruct from email");
        println!("  decrypt --text    : Reconstruct from text files");
        return;
    }
    
    match args[1].as_str() {
        "ShowKey" => show_key(),
        "decrypt" => {
            let mode = args.get(2).map(|s| s.as_str()).unwrap_or("--email");
            reconstruct_key(mode);
        }
        _ => println!("Usage: cargo run -- [ShowKey|decrypt]"),
    }
}

fn show_key() {
    match env::var("PRIVATE_KEY") {
        Ok(key) => println!("PRIVATE_KEY: {}", key),
        Err(_) => println!("PRIVATE_KEY not found in .env"),
    }
}

fn send_fragments(mode: &str) {
    let private_key = match env::var("PRIVATE_KEY") {
        Ok(key) => key,
        Err(_) => {
            println!("Error: PRIVATE_KEY not found in .env");
            return;
        }
    };

    let parts = split_into_five(&private_key);
    let mut rng = rand::thread_rng();
    let id: u64 = rng.gen_range(1111111111..9999999999);

    let a_str = "10060503295969647925188773225582035629579119017119701153283855496497048011514427577830152426024852561324895411104945235954430029508480410469752975231618183376933488700600605684330593584570331477701433707842590092720863168625943141102400636453246302513244279610482273498565515956680555941905582866804662138370";
    let n_str = "38285053399654906790389220378702848008742323419608895009569284984304409409133233347303906458700814581610889681569352487393278631944988763092927206984640198244905459087901267074160902715703719789485534589165585970754677786023766924324041327885094868782276204937000420963621376501608800903062748707010523890517";
    let a = a_str.parse::<BigUint>().unwrap();
    let n = n_str.parse::<BigUint>().unwrap();
    let t = 60000;

    let keypair_file = ".rust_keypair.bin";
    let keypair = if std::path::Path::new(keypair_file).exists() {
        println!("Loading existing keypair from {}", keypair_file);
        let data = std::fs::read(keypair_file).expect("Failed to read keypair file");
        let mut public = [0u8; KYBER_PUBLICKEYBYTES];
        let mut secret = [0u8; KYBER_SECRETKEYBYTES];
        public.copy_from_slice(&data[0..KYBER_PUBLICKEYBYTES]);
        secret.copy_from_slice(&data[KYBER_PUBLICKEYBYTES..]);
        pqc_kyber::Keypair { public, secret }
    } else {
        println!("Generating new keypair and saving to {}", keypair_file);
        let kp = keypair(&mut rng).expect("Failed to generate keypair");
        let mut data = Vec::new();
        data.extend_from_slice(&kp.public);
        data.extend_from_slice(&kp.secret);
        std::fs::write(keypair_file, data).expect("Failed to save keypair");
        kp
    };
    let receiver_pk = &keypair.public;

    for (i, part) in parts.iter().enumerate() {
        thread::sleep(Duration::from_millis(1200));

        let k = setup_key();
        println!("LOCKING MESSAGE part {}", i + 1);
        
        let lock_result = lock_message(part.as_bytes(), t, &n, &a, &k, &receiver_pk)
            .expect("Failed to lock message");
        
        println!("ID: {}", id);
        println!("LOCKED MESSAGE");

        if mode == "--text" {
            let filename = format!("fragment_{}.txt", i + 1);
            let content = format!(
                "pkfragment: {}\npkcipher: {}\ntlpuzzle: {}\npkmlid: {}\npkseq: {}\n",
                hex::encode(&lock_result.c),
                hex::encode(&lock_result.ciphertext),
                hex::encode(&lock_result.e),
                id,
                i + 1
            );
            std::fs::write(&filename, content).expect("Failed to write file");
            println!("Key part {} saved to {}", i + 1, filename);
        } else {
            if let Err(e) = send_email(
                &hex::encode(&lock_result.c),
                &hex::encode(&lock_result.e),
                &hex::encode(&lock_result.ciphertext),
                &id.to_string(),
                &(i + 1).to_string(),
            ) {
                println!("Error sending email: {}", e);
            } else {
                println!("Key part {} sent to Consortium", i + 1);
            }
        }
    }
}

fn split_into_five(s: &str) -> Vec<String> {
    let len = s.len();
    let part_len = len / 5;
    let remainder = len % 5;
    let mut result = Vec::new();
    let mut start = 0;

    for i in 0..5 {
        let mut end = start + part_len;
        if i < remainder {
            end += 1;
        }
        result.push(s[start..end].to_string());
        start = end;
    }
    result
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

fn reconstruct_key(mode: &str) {
    println!("Starting key reconstruction from {}...", if mode == "--text" { "files" } else { "emails" });
    
    let a_str = "10060503295969647925188773225582035629579119017119701153283855496497048011514427577830152426024852561324895411104945235954430029508480410469752975231618183376933488700600605684330593584570331477701433707842590092720863168625943141102400636453246302513244279610482273498565515956680555941905582866804662138370";
    let n_str = "38285053399654906790389220378702848008742323419608895009569284984304409409133233347303906458700814581610889681569352487393278631944988763092927206984640198244905459087901267074160902715703719789485534589165585970754677786023766924324041327885094868782276204937000420963621376501608800903062748707010523890517";
    let a = a_str.parse::<BigUint>().unwrap();
    let n = n_str.parse::<BigUint>().unwrap();
    let t = 60000;

    let keypair_file = ".rust_keypair.bin";
    let keypair = if std::path::Path::new(keypair_file).exists() {
        println!("Loading keypair from {}", keypair_file);
        let data = std::fs::read(keypair_file).expect("Failed to read keypair file");
        let mut public = [0u8; KYBER_PUBLICKEYBYTES];
        let mut secret = [0u8; KYBER_SECRETKEYBYTES];
        public.copy_from_slice(&data[0..KYBER_PUBLICKEYBYTES]);
        secret.copy_from_slice(&data[KYBER_PUBLICKEYBYTES..]);
        pqc_kyber::Keypair { public, secret }
    } else {
        println!("ERROR: Keypair file not found. Run SendFragments first.");
        return;
    };
    let receiver_sk = &keypair.secret;

    let mut key_storage: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let mut key_progress: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    if mode == "--text" {
        reconstruct_from_files(&a, &n, t, receiver_sk, &mut key_storage, &mut key_progress);
    } else {
        reconstruct_from_email(&a, &n, t, receiver_sk, &mut key_storage, &mut key_progress);
    }
}

fn reconstruct_from_files(
    a: &BigUint,
    n: &BigUint,
    t: usize,
    receiver_sk: &SecretKey,
    key_storage: &mut std::collections::HashMap<String, Vec<String>>,
    key_progress: &mut std::collections::HashMap<String, usize>,
) {
    for i in 1..=5 {
        let filename = format!("fragment_{}.txt", i);
        if !std::path::Path::new(&filename).exists() {
            println!("File {} not found", filename);
            continue;
        }
        
        let content = std::fs::read_to_string(&filename).expect("Failed to read file");
        let mut c = String::new();
        let mut e = String::new();
        let mut ciphertext = String::new();
        let mut id = String::new();
        let mut seq = String::new();
        
        for line in content.lines() {
            if line.starts_with("pkfragment:") {
                c = line.trim_start_matches("pkfragment:").trim().to_string();
            } else if line.starts_with("tlpuzzle:") {
                e = line.trim_start_matches("tlpuzzle:").trim().to_string();
            } else if line.starts_with("pkcipher:") {
                ciphertext = line.trim_start_matches("pkcipher:").trim().to_string();
            } else if line.starts_with("pkmlid:") {
                id = line.trim_start_matches("pkmlid:").trim().to_string();
            } else if line.starts_with("pkseq:") {
                seq = line.trim_start_matches("pkseq:").trim().to_string();
            }
        }

        if id.is_empty() {
            continue;
        }

        if !key_storage.contains_key(&id) {
            key_storage.insert(id.clone(), vec![String::new(); 5]);
            key_progress.insert(id.clone(), 0);
        }

        println!("Processing file {} with ID: {}, seq: {}", filename, id, seq);

        let c_bytes = hex::decode(&c).expect("Invalid C hex");
        let e_bytes = hex::decode(&e).expect("Invalid E hex");
        let ct_bytes = hex::decode(&ciphertext).expect("Invalid ciphertext hex");

        match unlock_message(&c_bytes, &e_bytes, a, n, t, &ct_bytes, receiver_sk) {
            Ok(recovered) => {
                let recovered_str = String::from_utf8_lossy(&recovered).to_string();
                let seq_num: usize = seq.parse().unwrap_or(1);
                if let Some(parts) = key_storage.get_mut(&id) {
                    if seq_num > 0 && seq_num <= 5 {
                        parts[seq_num - 1] = recovered_str;
                    }
                }
                *key_progress.get_mut(&id).unwrap() += 1;

                if *key_progress.get(&id).unwrap() >= 5 {
                    println!("All parts received for ID: {}", id);
                    let final_message = key_storage.get(&id).unwrap().join("");
                    println!("Private key: {}", final_message);
                }
            }
            Err(e) => println!("Error unlocking message: {}", e),
        }
    }
}

fn reconstruct_from_email(
    a: &BigUint,
    n: &BigUint,
    t: usize,
    receiver_sk: &SecretKey,
    key_storage: &mut std::collections::HashMap<String, Vec<String>>,
    key_progress: &mut std::collections::HashMap<String, usize>,
) {
    let imap_host = env::var("MAIL_IMAP_HOST").expect("MAIL_IMAP_HOST not set");
    let imap_port = env::var("MAIL_IMAP_PORT").unwrap_or("993".to_string());
    let imap_user = env::var("MAIL_IMAP_USERNAME").expect("MAIL_IMAP_USERNAME not set");
    let imap_pass = env::var("MAIL_IMAP_PASSWORD").expect("MAIL_IMAP_PASSWORD not set");

    println!("Connecting to IMAP server: {}:{}", imap_host, imap_port);
    let tls = native_tls::TlsConnector::builder().build().unwrap();
    let client = imap::connect((imap_host.as_str(), imap_port.parse::<u16>().unwrap()), &imap_host, &tls)
        .expect("Failed to connect to IMAP server");

    let mut imap_session = client.login(&imap_user, &imap_pass)
        .map_err(|e| e.0)
        .expect("Failed to login to IMAP");

    imap_session.select("INBOX").expect("Failed to select INBOX");

    let messages = imap_session
        .search("SUBJECT \"MAIL PRIVATE KEY\"")
        .expect("Failed to search emails");

    println!("Found {} messages total", messages.len());

    if messages.is_empty() {
        println!("No messages found!");
        imap_session.logout().ok();
        return;
    }

    let mut msg_vec: Vec<_> = messages.iter().cloned().collect();
    msg_vec.sort();
    let recent_messages: Vec<_> = msg_vec.iter().rev().take(5).cloned().collect();

    for msg_id in recent_messages.iter() {
        let messages = imap_session
            .fetch(msg_id.to_string(), "RFC822")
            .expect("Failed to fetch message");

        for message in messages.iter() {
            if let Some(body) = message.body() {
                let parsed = mailparse::parse_mail(body).expect("Failed to parse email");
                let body_text = parsed.get_body().unwrap_or_default();
                
                let mut c = String::new();
                let mut e = String::new();
                let mut ciphertext = String::new();
                let mut id = String::new();
                let mut seq = String::new();
                
                for line in body_text.lines() {
                    if line.starts_with("pkfragment:") {
                        c = line.trim_start_matches("pkfragment:").trim().to_string();
                    } else if line.starts_with("tlpuzzle:") {
                        e = line.trim_start_matches("tlpuzzle:").trim().to_string();
                    } else if line.starts_with("pkcipher:") {
                        ciphertext = line.trim_start_matches("pkcipher:").trim().to_string();
                    } else if line.starts_with("pkmlid:") {
                        id = line.trim_start_matches("pkmlid:").trim().to_string();
                    } else if line.starts_with("pkseq:") {
                        seq = line.trim_start_matches("pkseq:").trim().to_string();
                    }
                }

                if id.is_empty() {
                    continue;
                }

                if !key_storage.contains_key(&id) {
                    key_storage.insert(id.clone(), vec![String::new(); 5]);
                    key_progress.insert(id.clone(), 0);
                }

                let c_bytes = hex::decode(&c).expect("Invalid C hex");
                let e_bytes = hex::decode(&e).expect("Invalid E hex");
                let ct_bytes = hex::decode(&ciphertext).expect("Invalid ciphertext hex");

                match unlock_message(&c_bytes, &e_bytes, a, n, t, &ct_bytes, receiver_sk) {
                    Ok(recovered) => {
                        let recovered_str = String::from_utf8_lossy(&recovered).to_string();
                        let seq_num: usize = seq.parse().unwrap_or(1);
                        if let Some(parts) = key_storage.get_mut(&id) {
                            if seq_num > 0 && seq_num <= 5 {
                                parts[seq_num - 1] = recovered_str;
                            }
                        }
                        *key_progress.get_mut(&id).unwrap() += 1;

                        if *key_progress.get(&id).unwrap() >= 5 {
                            println!("All parts received for ID: {}", id);
                            let final_message = key_storage.get(&id).unwrap().join("");
                            println!("Private key: {}", final_message);
                        }
                    }
                    Err(e) => println!("Error unlocking message: {}", e),
                }
            }
        }
    }

    imap_session.logout().ok();
}
