use std::fs::File;
use std::io::Read;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use rayon::prelude::*;
use sha2::{Sha256, Sha512, Digest};
use md5::Md5;
use clap::Parser;
use memmap2::Mmap;

#[derive(Parser)]
#[command(name = "binary_scanner")]
#[command(about = "核心二进制扫描引擎 - Parallel Signature Detection & Hash Calculation")]
struct Cli {
    #[arg(long)]
    file: String,
    
    #[arg(long, default_value = "parallel")]
    mode: String,
    
    #[arg(long, default_value = "sha256,sha512,md5")]
    hashes: String,
    
    #[arg(long)]
    yara_scan: bool,
    
    #[arg(long)]
    entropy: bool,
}

#[derive(Debug, serde::Serialize)]
struct ScanResult {
    file_path: String,
    file_size: u64,
    hashes: HashMap<String, String>,
    entropy_score: f64,
    entropy_level: String,
    yara_matches: Vec<String>,
    suspicious_sections: Vec<SectionAnalysis>,
    scan_duration_ms: u64,
    scan_mode: String,
}

#[derive(Debug, serde::Serialize)]
struct SectionAnalysis {
    offset: u64,
    size: usize,
    entropy: f64,
    suspicious: bool,
    section_type: String,
}

fn calculate_entropy_parallel(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    
    let chunk_size = data.len() / rayon::current_num_threads().max(1);
    if chunk_size == 0 {
        return calculate_entropy_single(data);
    }
    
    let frequencies: Vec<[u64; 256]> = data
        .par_chunks(chunk_size)
        .map(|chunk| {
            let mut freq = [0u64; 256];
            for &byte in chunk {
                freq[byte as usize] += 1;
            }
            freq
        })
        .collect();
    
    let mut total_freq = [0u64; 256];
    for freq in frequencies {
        for i in 0..256 {
            total_freq[i] += freq[i];
        }
    }
    
    let length = data.len() as f64;
    let entropy: f64 = total_freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / length;
            -p * p.log2()
        })
        .sum();
    
    entropy / 8.0
}

fn calculate_entropy_single(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    
    let mut frequencies = [0u64; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }
    
    let length = data.len() as f64;
    let entropy: f64 = frequencies.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / length;
            -p * p.log2()
        })
        .sum();
    
    entropy / 8.0
}

fn analyze_sections(data: &[u8], section_size: usize) -> Vec<SectionAnalysis> {
    if data.is_empty() || section_size == 0 {
        return Vec::new();
    }
    
    data.par_chunks(section_size)
        .enumerate()
        .map(|(i, chunk)| {
            let entropy = calculate_entropy_single(chunk);
            SectionAnalysis {
                offset: (i * section_size) as u64,
                size: chunk.len(),
                entropy,
                suspicious: entropy > 0.85,
                section_type: if entropy > 0.90 {
                    "Highly Entropic - Possibly Encrypted/Compressed".to_string()
                } else if entropy > 0.85 {
                    "Moderately Entropic - Requires Investigation".to_string()
                } else {
                    "Normal Data".to_string()
                },
            }
        })
        .collect()
}

fn scan_yara_patterns(data: &[u8]) -> Vec<String> {
    let mut matches = Vec::new();
    
    let patterns = vec![
        ("MZ_PE_Header", &b"MZ"[..], "Windows PE Executable signature detected"),
        ("PE_Signature", &b"PE\0\0"[..], "PE Optional Header found"),
        ("PDF_JavaScript", &b"/JavaScript"[..], "PDF JavaScript object detected"),
        ("PDF_OpenAction", &b"/OpenAction"[..], "PDF automatic action detected"),
        ("PDF_Launch", &b"/Launch"[..], "PDF launch action - potential exploit"),
        ("OLE_Macro_AutoOpen", &b"AutoOpen"[..], "OLE AutoOpen macro - high risk"),
        ("OLE_Macro_DocumentOpen", &b"Document_Open"[..], "Document Open macro trigger"),
        ("PowerShell_Encoded", &b"-enc "[..], "Encoded PowerShell command"),
        ("PowerShell_ExecutionPolicy", &b"ExecutionPolicy Bypass"[..], "PowerShell policy bypass attempt"),
        ("Base64_Encoded_PE", &b"TVqQAAMAAAA"[..], "Base64 encoded PE executable"),
        ("Shellcode_NOP_Sled", &b"\x90\x90\x90\x90\x90"[..], "NOP sled - possible shellcode"),
        ("Reverse_Shell_Bash", &b"/dev/tcp/"[..], "Bash reverse shell attempt"),
        ("SQL_Injection_Basic", &b"UNION SELECT"[..], "SQL injection pattern"),
        ("XSS_Basic", &b"<script>"[..], "Cross-site scripting pattern"),
    ];
    
    for (pattern_name, pattern_bytes, description) in patterns {
        let matches_count = data
            .par_windows(pattern_bytes.len())
            .filter(|window| *window == pattern_bytes)
            .count();
        
        if matches_count > 0 {
            matches.push(format!(
                "{}: {} (found {} occurrences)",
                pattern_name, description, matches_count
            ));
        }
    }
    
    matches
}

fn calculate_hashes(data: &[u8], hash_types: &[&str]) -> HashMap<String, String> {
    hash_types.par_iter()
        .map(|&hash_type| {
            match hash_type.trim() {
                "sha256" => {
                    let mut hasher = Sha256::new();
                    hasher.update(data);
                    ("SHA256".to_string(), format!("{:x}", hasher.finalize()))
                },
                "sha512" => {
                    let mut hasher = Sha512::new();
                    hasher.update(data);
                    ("SHA512".to_string(), format!("{:x}", hasher.finalize()))
                },
                "md5" => {
                    let mut hasher = Md5::new();
                    hasher.update(data);
                    ("MD5".to_string(), format!("{:x}", hasher.finalize()))
                },
                _ => ("Unknown".to_string(), "Unsupported hash type".to_string()),
            }
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let start_time = Instant::now();
    
    let file = File::open(&cli.file)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let data = &mmap[..];
    
    let hash_types: Vec<&str> = cli.hashes.split(',').collect();
    let hashes = calculate_hashes(data, &hash_types);
    
    let entropy_score = if cli.entropy {
        calculate_entropy_parallel(data)
    } else {
        0.0
    };
    
    let entropy_level = if entropy_score > 0.90 {
        "CRITICAL".to_string()
    } else if entropy_score > 0.85 {
        "HIGH".to_string()
    } else if entropy_score > 0.70 {
        "MEDIUM".to_string()
    } else {
        "LOW".to_string()
    };
    
    let suspicious_sections = if entropy_score > 0.70 {
        analyze_sections(data, 4096)
    } else {
        Vec::new()
    };
    
    let yara_matches = if cli.yara_scan {
        scan_yara_patterns(data)
    } else {
        Vec::new()
    };
    
    let result = ScanResult {
        file_path: cli.file.clone(),
        file_size: data.len() as u64,
        hashes,
        entropy_score: (entropy_score * 10000.0).round() / 10000.0,
        entropy_level,
        yara_matches,
        suspicious_sections,
        scan_duration_ms: start_time.elapsed().as_millis() as u64,
        scan_mode: cli.mode.clone(),
    };
    
    println!("{}", serde_json::to_string_pretty(&result)?);
    
    Ok(())
}