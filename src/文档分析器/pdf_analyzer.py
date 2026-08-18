import sys
import json
import zlib
import re
import math
from collections import defaultdict
from typing import Dict, List, Any
from datetime import datetime
import io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def decode_pdf_string(data: bytes) -> str:
    if data.startswith(b'\xfe\xff'):
        try:
            return data[2:].decode('utf-16-be', errors='replace')
        except:
            pass
    elif data.startswith(b'\xff\xfe'):
        try:
            return data[2:].decode('utf-16-le', errors='replace')
        except:
            pass
    elif data.startswith(b'\xef\xbb\xbf'):
        try:
            return data[3:].decode('utf-8', errors='replace')
        except:
            pass
    try:
        return data.decode('utf-8', errors='replace')
    except:
        return data.decode('ascii', errors='replace')

class PDFDeepAnalyzer:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings = {
            "suspicious_objects": [],
            "javascript_injections": [],
            "compressed_streams": [],
            "structural_anomalies": [],
            "metadata_extraction": {},
            "risk_score": 0.0,
            "analysis_timestamp": "",
            "chinese_encoding_detected": False,
            "embedded_files": [],
            "total_streams": 0,
            "pdf_version": "",
            "encryption_info": {}
        }
        
    def analyze(self) -> Dict[str, Any]:
        self.findings["analysis_timestamp"] = datetime.now().isoformat()
        
        with open(self.filepath, 'rb') as f:
            self.data = f.read()
        
        self._detect_pdf_version()
        self._detect_pdf_header()
        self._extract_javascript()
        self._analyze_streams()
        self._detect_obfuscation()
        self._extract_metadata()
        self._detect_encryption()
        self._calculate_risk_score()
        self._detect_chinese_encoding()
        
        return self.findings
    
    def _detect_pdf_version(self):
        version_match = re.match(rb'%PDF-(\d+\.\d+)', self.data)
        if version_match:
            self.findings["pdf_version"] = version_match.group(1).decode('ascii')
    
    def _detect_pdf_header(self):
        if not self.data.startswith(b'%PDF'):
            self.findings["structural_anomalies"].append({
                "type": "Invalid PDF Header",
                "severity": "HIGH",
                "description": "File missing standard PDF header"
            })
    
    def _extract_javascript(self):
        js_patterns = [
            (rb'/JavaScript\s*<<', "JavaScript Object"),
            (rb'/JS\s*<<', "JS Object"),
            (rb'/JavaScript\s*\([^)]*\)', "JavaScript String"),
            (rb'/JS\s*\([^)]*\)', "JS String"),
            (rb'this\.exportDataObject', "Data Export API"),
            (rb'app\.launchURL', "URL Launch API"),
            (rb'eval\s*\(', "eval() call"),
            (rb'unescape\s*\(', "unescape() call"),
            (rb'String\.fromCharCode', "CharCode Obfuscation"),
            (rb'ActiveXObject', "ActiveX Instantiation"),
        ]
        
        for pattern, description in js_patterns:
            matches = re.finditer(pattern, self.data, re.IGNORECASE | re.DOTALL)
            for match in matches:
                context_start = max(0, match.start() - 40)
                context_end = min(len(self.data), match.end() + 40)
                context = self.data[context_start:context_end]
                context_str = context.decode('ascii', errors='replace')
                
                self.findings["javascript_injections"].append({
                    "type": description,
                    "offset": match.start(),
                    "context": context_str[:80],
                    "severity": "HIGH" if b'eval' in pattern.lower() or b'ActiveX' in pattern else "MEDIUM"
                })
    
    def _analyze_streams(self):
        stream_pattern = rb'stream\s+(.*?)\s+endstream'
        matches = re.finditer(stream_pattern, self.data, re.DOTALL)
        
        for match in matches:
            self.findings["total_streams"] += 1
            stream_data = match.group(1)
            try:
                decompressed = zlib.decompress(stream_data)
                entropy = self._calculate_entropy(decompressed)
                
                if entropy > 0.85:
                    self.findings["compressed_streams"].append({
                        "offset": match.start(),
                        "original_size": len(stream_data),
                        "decompressed_size": len(decompressed),
                        "entropy": round(entropy, 4),
                        "suspicious": entropy > 0.92,
                        "contains_text": self._contains_readable_text(decompressed),
                        "type": "High entropy compressed stream"
                    })
            except:
                pass
    
    def _contains_readable_text(self, data: bytes) -> bool:
        try:
            text = data.decode('utf-8', errors='ignore')
            printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
            return printable / len(text) > 0.3 if len(text) > 0 else False
        except:
            return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        frequencies = defaultdict(int)
        for byte in data:
            frequencies[byte] += 1
        entropy = 0.0
        data_len = len(data)
        for freq in frequencies.values():
            probability = freq / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy / 8.0
    
    def _detect_obfuscation(self):
        obfuscation_indicators = [
            (rb'\/Filter\s*\/FlateDecode', "Standard FlateDecode compression"),
            (rb'\/Filter\s*\/ASCIIHexDecode', "ASCII Hex encoding - suspicious"),
            (rb'\/Filter\s*\/ASCII85Decode', "ASCII85 encoding - highly suspicious"),
            (rb'\/Filter\s*\/Crypt', "Encryption filter detected"),
            (rb'\/OpenAction', "Auto-open action detected"),
            (rb'\/AA\s*<<', "Automatic action detected"),
            (rb'\/Launch\s*\(', "Launch action detected"),
            (rb'\/EmbeddedFile', "Embedded file detected"),
            (rb'\/RichMedia', "Rich media content detected"),
        ]
        
        for pattern, description in obfuscation_indicators:
            if re.search(pattern, self.data, re.IGNORECASE):
                self.findings["structural_anomalies"].append({
                    "type": description,
                    "risk": "HIGH" if b"ASCII" in pattern or b"Launch" in pattern or b"EmbeddedFile" in pattern or b"RichMedia" in pattern else "INFO"
                })
    
    def _extract_metadata(self):
        metadata_fields = {
            b'/Title': 'title',
            b'/Author': 'author',
            b'/Subject': 'subject',
            b'/Creator': 'creator',
            b'/Producer': 'producer',
            b'/Keywords': 'keywords',
            b'/CreationDate': 'creation_date',
            b'/ModDate': 'modification_date'
        }
        
        for pattern, field_name in metadata_fields.items():
            regex = pattern + rb'\s*\((.*?)\)'
            matches = re.findall(regex, self.data, re.DOTALL)
            if matches:
                values = []
                for m in matches:
                    decoded = decode_pdf_string(m)
                    cleaned = decoded.replace('\x00', '').strip()
                    if cleaned:
                        values.append(cleaned)
                if values:
                    self.findings["metadata_extraction"][field_name] = values
    
    def _detect_encryption(self):
        if b'/Encrypt' in self.data:
            self.findings["encryption_info"] = {
                "encrypted": True,
                "warning": "PDF is encrypted - analysis may be limited"
            }
            if b'/V 1' in self.data or b'/V 2' in self.data or b'/V 3' in self.data:
                self.findings["encryption_info"]["weak_encryption"] = True
                self.findings["structural_anomalies"].append({
                    "type": "Weak PDF encryption version detected",
                    "risk": "HIGH"
                })
    
    def _detect_chinese_encoding(self):
        chinese_pattern = rb'[\xe4-\xe9][\x80-\xbf]{2,}'
        matches = re.findall(chinese_pattern, self.data)
        if len(matches) > 10:
            self.findings["chinese_encoding_detected"] = True
    
    def _calculate_risk_score(self):
        total_risk = 0
        if self.findings["javascript_injections"]:
            total_risk += 25 * len(self.findings["javascript_injections"])
        if self.findings["compressed_streams"]:
            high_entropy_streams = [s for s in self.findings["compressed_streams"] if s["suspicious"]]
            total_risk += 15 * len(high_entropy_streams)
        if self.findings["structural_anomalies"]:
            high_risk_anomalies = [a for a in self.findings["structural_anomalies"] if a.get("risk") == "HIGH"]
            total_risk += 20 * len(high_risk_anomalies)
        if self.findings["encryption_info"].get("weak_encryption"):
            total_risk += 25
        
        self.findings["risk_score"] = min(100, total_risk)
        
        if total_risk >= 70:
            self.findings["risk_level"] = "CRITICAL"
        elif total_risk >= 40:
            self.findings["risk_level"] = "HIGH"
        elif total_risk >= 15:
            self.findings["risk_level"] = "MEDIUM"
        else:
            self.findings["risk_level"] = "LOW"

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='PDF Deep Analysis Engine')
    parser.add_argument('--file', required=True, help='PDF file path')
    parser.add_argument('--deep-analysis', action='store_true')
    parser.add_argument('--extract-javascript', action='store_true')
    parser.add_argument('--detect-streams', action='store_true')
    args = parser.parse_args()
    try:
        analyzer = PDFDeepAnalyzer(args.file)
        results = analyzer.analyze()
        print(json.dumps(results, indent=2, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({"error": str(e), "status": "ANALYSIS_FAILED"}, indent=2, ensure_ascii=False))
