use std::env;
use dotenv::dotenv;
use lettre::{SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use lettre::address::Address;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::signature::{SignatureEncoding, Signer};

type HmacSha256 = Hmac<Sha256>;

fn load_dkim_key(domain: &str, epoch_id: &str) -> Option<(RsaPrivateKey, String, String)> {
    let dkim_path = format!("NAEF/dsmtp/{}/{}_dkim.txt",
        domain.replace('.', "_"), domain.replace('.', "_"));

    let content = match std::fs::read_to_string(&dkim_path) {
        Ok(c) => c,
        Err(_) => {
            println!("Error: {} not found. Run 'kda eka {} {}' first.", dkim_path, domain, epoch_id);
            return None;
        }
    };

    let epoch_marker = format!("[epoch:{}]", epoch_id);
    let mut found = false;
    let mut private_key_b64 = String::new();
    let mut public_key_b64 = String::new();
    let mut selector = String::new();

    for line in content.lines() {
        if line == epoch_marker {
            found = true;
            private_key_b64.clear();
            public_key_b64.clear();
            selector.clear();
            continue;
        }
        if found {
            if line.starts_with("[epoch:") { break; }
            if let Some(v) = line.strip_prefix("private_key:") { private_key_b64 = v.trim().to_string(); }
            else if let Some(v) = line.strip_prefix("public_key:") { public_key_b64 = v.trim().to_string(); }
            else if let Some(v) = line.strip_prefix("selector:") { selector = v.trim().to_string(); }
        }
    }

    if !found || private_key_b64.is_empty() {
        println!("Error: Epoch {} not found in {}.", epoch_id, dkim_path);
        return None;
    }

    let mut pem_body = String::new();
    for (i, chunk) in private_key_b64.as_bytes().chunks(64).enumerate() {
        if i > 0 { pem_body.push('\n'); }
        pem_body.push_str(&String::from_utf8_lossy(chunk));
    }
    let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----", pem_body);

    let private_key = match RsaPrivateKey::from_pkcs8_pem(&pem) {
        Ok(k) => k,
        Err(e) => {
            println!("Error parsing RSA private key: {}", e);
            return None;
        }
    };

    Some((private_key, public_key_b64, selector))
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn hex_encode_lower(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn dkim_sign(signing_key: &RsaPrivateKey, domain: &str, selector: &str, from: &str, to: &str, subject: &str, body: &str) -> String {
    // Body canonicalization (simple): body as-is, ensure ends with CRLF
    let canon_body = if body.ends_with("\r\n") {
        body.to_string()
    } else {
        format!("{}\r\n", body)
    };

    let body_hash = {
        let mut h = Sha256::new();
        h.update(canon_body.as_bytes());
        base64_encode(&h.finalize())
    };

    // DKIM-Signature value with b= empty
    let dkim_value_without_b = format!(
        "v=1; a=rsa-sha256; d={}; s={}; c=relaxed/simple; h=from:to:subject; bh={}; b=",
        domain, selector, body_hash
    );

    // Header canonicalization (relaxed): lowercase names, collapse WSP, no trailing CRLF on last
    let canon_headers = format!(
        "from:{}\r\nto:{}\r\nsubject:{}\r\ndkim-signature:{}",
        from.split_whitespace().collect::<Vec<&str>>().join(" "),
        to.split_whitespace().collect::<Vec<&str>>().join(" "),
        subject.split_whitespace().collect::<Vec<&str>>().join(" "),
        dkim_value_without_b.split_whitespace().collect::<Vec<&str>>().join(" ")
    );

    let rsa_signing_key = RsaSigningKey::<Sha256>::new(signing_key.clone());
    let signature = rsa_signing_key.sign(canon_headers.as_bytes());
    let sig_b64 = base64_encode(&signature.to_bytes());

    format!("v=1; a=rsa-sha256; d={}; s={}; c=relaxed/simple; h=from:to:subject; bh={}; b={}",
        domain, selector, body_hash, sig_b64)
}


fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC error");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn send_via_ses_api(raw_message: &str, from_addr: &str, to_addr: &str) -> Result<(), String> {
    let region = env::var("AWS_SES_REGION").unwrap_or_else(|_| {
        // Extract region from SMTP host: email-smtp.ap-south-1.amazonaws.com
        let host = env::var("Mail_SMTP_HOST").unwrap_or_default();
        host.strip_prefix("email-smtp.")
            .and_then(|s| s.strip_suffix(".amazonaws.com"))
            .unwrap_or("ap-south-1")
            .to_string()
    });

    let access_key = env::var("AWS_ACCESS_KEY_ID")
        .or_else(|_| env::var("MAIL_SMTP_USERNAME"))
        .map_err(|_| "AWS_ACCESS_KEY_ID or MAIL_SMTP_USERNAME not set")?;
    let secret_key = env::var("AWS_SECRET_ACCESS_KEY")
        .map_err(|_| "AWS_SECRET_ACCESS_KEY not set. Note: SES SMTP password is NOT the same as IAM secret key.")?;

    let service = "ses";
    let host = format!("email.{}.amazonaws.com", region);
    let endpoint = format!("https://{}/", host);

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let raw_b64 = base64_encode(raw_message.as_bytes());

    // Request body
    let request_body = format!(
        "Action=SendRawEmail&Source={}&Destinations.member.1={}&RawMessage.Data={}",
        urlencod(from_addr), urlencod(to_addr), urlencod(&raw_b64)
    );

    let payload_hash = hex_encode_lower(&sha256_hash(request_body.as_bytes()));

    // Canonical request
    let canonical_request = format!(
        "POST\n/\n\ncontent-type:application/x-www-form-urlencoded\nhost:{}\nx-amz-date:{}\n\ncontent-type;host;x-amz-date\n{}",
        host, amz_date, payload_hash
    );

    let canonical_request_hash = hex_encode_lower(&sha256_hash(canonical_request.as_bytes()));

    // String to sign
    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_request_hash
    );

    // Signing key
    let k_date = hmac_sha256(format!("AWS4{}", secret_key).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    let signature = hex_encode_lower(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders=content-type;host;x-amz-date, Signature={}",
        access_key, credential_scope, signature
    );

    let client = reqwest::blocking::Client::new();
    let response = client.post(&endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Host", &host)
        .header("X-Amz-Date", &amz_date)
        .header("Authorization", &authorization)
        .body(request_body)
        .send()
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let status = response.status();
    let body = response.text().unwrap_or_default();

    if status.is_success() {
        Ok(())
    } else {
        Err(format!("SES API error ({}): {}", status, body))
    }
}

fn urlencod(s: &str) -> String {
    let mut result = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

fn show_key(domain: &str, epoch_id: &str) {
    match load_dkim_key(domain, epoch_id) {
        Some((_sk, pubkey, selector)) => {
            println!("DKIM Key for {}/{}:", domain, epoch_id);
            println!("  domain:     {}", domain);
            println!("  selector:   {}", selector);
            println!("  epoch_id:   {}", epoch_id);
            println!("  public_key: {}...{}", &pubkey[..20], &pubkey[pubkey.len()-20..]);
            println!("  algorithm:  rsa-sha256");
        }
        None => {
            println!("Error: Could not load DKIM key for {}/{}.", domain, epoch_id);
        }
    }
}

fn send_mail(domain: &str, epoch_id: &str, to_addr: &str, mode: &str) {
    match dotenv() {
        Ok(path) => println!("Loaded .env from: {:?}", path),
        Err(e) => println!("Warning: Could not load .env: {}", e),
    }

    let (private_key, _pubkey, selector) = match load_dkim_key(domain, epoch_id) {
        Some(k) => k,
        None => {
            println!("Error: Could not load DKIM key for {}/{}.", domain, epoch_id);
            return;
        }
    };

    let from_addr = format!("noreply@{}", domain);
    let from_display = format!("NAEF DSMTP <{}>", from_addr);

    let subject = format!("NAEF Email Message for Epoch: {}", epoch_id);
    let body = format!(
        "Dear Recipient,\r\n\r\n\
        This is an email message sent using the NAEF DSMTP service which is a Non Attributable Email Service.\r\n\
        This email is being sent for the epoch Id: {}.\r\n\r\n\
        All the best,\r\n\
        NAEF",
        epoch_id
    );

    let dkim_sig = dkim_sign(&private_key, domain, &selector, &from_display, to_addr, &subject, &body);
    println!("DKIM Signature generated:");
    println!("  algorithm: rsa-sha256");
    println!("  selector:  {}", selector);
    println!("  mode:      {}", mode);

    let message_id = format!("<{}.{}@{}>",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        std::process::id(), domain);

    let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000").to_string();

    let raw_message = format!(
        "DKIM-Signature: {}\r\nFrom: {}\r\nTo: {}\r\nSubject: {}\r\nDate: {}\r\nMessage-ID: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n{}",
        dkim_sig, from_display, to_addr, subject, date, message_id, body
    );

    println!("\nSending email...");
    println!("  From:    {}", from_addr);
    println!("  To:      {}", to_addr);
    println!("  Subject: {}", subject);
    println!("  Domain:  {}", domain);
    println!("  Epoch:   {}", epoch_id);

    match mode {
        "--api" => {
            println!("  Method:  SES SendRawEmail API");
            match send_via_ses_api(&raw_message, &from_addr, to_addr) {
                Ok(_) => {
                    println!("\n✓ Email sent successfully via SES API!");
                    println!("  DKIM signed with RSA key from {}/{}", domain, epoch_id);
                    println!("  Headers preserved (no SES modification)");
                }
                Err(e) => {
                    println!("\n✗ Failed to send email: {}", e);
                }
            }
        }
        _ => {
            println!("  Method:  SMTP relay");
            let smtp_host = env::var("Mail_SMTP_HOST").expect("Mail_SMTP_HOST not set");
            let smtp_user = env::var("MAIL_SMTP_USERNAME").expect("MAIL_SMTP_USERNAME not set");
            let smtp_pass = env::var("MAIL_SMTP_PASSWORD").expect("MAIL_SMTP_PASSWORD not set");

            let from_address: Address = from_addr.parse().expect("Invalid from address");
            let to_address: Address = to_addr.parse().expect("Invalid to address");
            let envelope = lettre::address::Envelope::new(
                Some(from_address),
                vec![to_address],
            ).expect("Failed to create envelope");

            let creds = Credentials::new(smtp_user, smtp_pass);
            let mailer = SmtpTransport::relay(&smtp_host)
                .expect("Failed to create SMTP transport")
                .credentials(creds)
                .build();

            match mailer.send_raw(&envelope, raw_message.as_bytes()) {
                Ok(_) => {
                    println!("\n✓ Email sent successfully via SMTP!");
                    println!("  DKIM signed with RSA key from {}/{}", domain, epoch_id);
                    println!("  Note: SES may modify headers (DKIM may fail verification)");
                }
                Err(e) => {
                    println!("\n✗ Failed to send email: {}", e);
                }
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: dsmtp <command>");
        println!();
        println!("Commands:");
        println!("  ShowKey <domain> <epoch_id>                    Display DKIM signing key");
        println!("  SendMail <domain> <epoch_id> <to> [--smtp|--api]  Send DKIM-signed email");
        println!();
        println!("Send modes:");
        println!("  --smtp  Send via SES SMTP relay (default). SES may modify headers.");
        println!("  --api   Send via SES SendRawEmail API. Headers preserved exactly.");
        println!();
        println!("Environment variables:");
        println!("  --smtp: Mail_SMTP_HOST, MAIL_SMTP_USERNAME, MAIL_SMTP_PASSWORD");
        println!("  --api:  AWS_ACCESS_KEY_ID (or MAIL_SMTP_USERNAME), AWS_SECRET_ACCESS_KEY, AWS_SES_REGION");
        println!();
        println!("Notes:");
        println!("  - DKIM-Signature injected as first header in raw email");
        println!("  - Use --api for DKIM verification to pass at recipient");
        println!("  - Selector: naef-<epoch_id>._domainkey.<domain>");
        println!("  - From address: noreply@<domain>");
        return;
    }

    match args[1].as_str() {
        "ShowKey" => {
            if args.len() < 4 {
                println!("Usage: dsmtp ShowKey <domain> <epoch_id>");
                return;
            }
            show_key(&args[2], &args[3]);
        }
        "SendMail" => {
            if args.len() < 5 {
                println!("Usage: dsmtp SendMail <domain> <epoch_id> <to_email> [--smtp|--api]");
                return;
            }
            let mode = args.get(5).map(|s| s.as_str()).unwrap_or("--smtp");
            send_mail(&args[2], &args[3], &args[4], mode);
        }
        _ => {
            println!("Unknown command. Run 'dsmtp' without arguments for help.");
        }
    }
}
