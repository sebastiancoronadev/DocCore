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
#[command(about = "核心二进制扫描引擎 - 并行模式匹配与哈希计算")]
struct Cli {
    #[arg(long)]
    file: String,
    
    #[arg(long, default_value = "parallel")]
    mode: String,
    
    #[arg(long, default_value = "sha256,sha512,md5")]
    hashes: String,
    
    #[arg(long)]
    pattern_scan: bool,
    
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
    pattern_matches: Vec<String>,
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
                    "高度熵值 - 可能加密或压缩".to_string()
                } else if entropy > 0.85 {
                    "中高熵值 - 需要调查".to_string()
                } else {
                    "正常数据".to_string()
                },
            }
        })
        .collect()
}

fn scan_binary_patterns(data: &[u8]) -> Vec<String> {
    let mut matches = Vec::new();
    
    let patterns = vec![
        ("MZ_PE文件头", &b"MZ"[..], "Windows PE可执行文件签名"),
        ("PE签名", &b"PE\0\0"[..], "PE可选头"),
        ("PDF_JavaScript", &b"/JavaScript"[..], "PDF JavaScript对象"),
        ("PDF_OpenAction", &b"/OpenAction"[..], "PDF自动动作"),
        ("PDF_Launch", &b"/Launch"[..], "PDF启动动作"),
        ("OLE_AutoOpen宏", &b"AutoOpen"[..], "OLE自动打开宏"),
        ("OLE_DocumentOpen宏", &b"Document_Open"[..], "文档打开宏触发器"),
        ("PowerShell_Encoded", &b"-enc "[..], "编码的PowerShell命令"),
        ("PowerShell_Bypass", &b"ExecutionPolicy Bypass"[..], "PowerShell策略绕过"),
        ("Base64_PE编码", &b"TVqQAAMAAAA"[..], "Base64编码的PE可执行文件"),
        ("Shellcode_NOP滑板", &b"\x90\x90\x90\x90\x90"[..], "NOP滑板 - 可能的shellcode"),
        ("Bash反向Shell", &b"/dev/tcp/"[..], "Bash反向shell尝试"),
        ("SQL注入", &b"UNION SELECT"[..], "SQL注入模式"),
        ("XSS攻击", &b"<script>"[..], "跨站脚本模式"),
    ];
    
    for (pattern_name, pattern_bytes, description) in patterns {
        let matches_count = data
            .par_windows(pattern_bytes.len())
            .filter(|window| *window == pattern_bytes)
            .count();
        
        if matches_count > 0 {
            matches.push(format!(
                "{}: {} (发现{}处)",
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
                _ => ("Unknown".to_string(), "Unsupported".to_string()),
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
        "严重".to_string()
    } else if entropy_score > 0.85 {
        "高危".to_string()
    } else if entropy_score > 0.70 {
        "中危".to_string()
    } else {
        "低危".to_string()
    };
    
    let suspicious_sections = if entropy_score > 0.70 {
        analyze_sections(data, 4096)
    } else {
        Vec::new()
    };
    
    let pattern_matches = if cli.pattern_scan {
        scan_binary_patterns(data)
    } else {
        Vec::new()
    };
    
    let result = ScanResult {
        file_path: cli.file.clone(),
        file_size: data.len() as u64,
        hashes,
        entropy_score: (entropy_score * 10000.0).round() / 10000.0,
        entropy_level,
        pattern_matches,
        suspicious_sections,
        scan_duration_ms: start_time.elapsed().as_millis() as u64,
        scan_mode: cli.mode.clone(),
    };
    
    println!("{}", serde_json::to_string_pretty(&result)?);
    
    Ok(())
}
