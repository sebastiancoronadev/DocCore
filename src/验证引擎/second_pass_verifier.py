import sys
import json
import hashlib
import os
import struct
import zlib
from typing import Dict, Any, List, Tuple

class SecondPassVerifier:
    def __init__(self):
        self.checks_passed = 0
        self.checks_failed = 0
        self.findings = []
    
    def verify_pdf_complete(self, file_path: str) -> Dict[str, Any]:
        result = {
            "format": "PDF",
            "checks": [],
            "overall_status": "PENDING",
            "active_content_free": False,
            "structurally_valid": False,
            "hash_verified": False
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            result["checks"].append(self._check_pdf_header(content))
            result["checks"].append(self._check_javascript_objects(content))
            result["checks"].append(self._check_embedded_files(content))
            result["checks"].append(self._check_automatic_actions(content))
            result["checks"].append(self._check_dangerous_filters(content))
            result["checks"].append(self._check_xref_structure(content))
            
            self.checks_passed = sum(1 for c in result["checks"] if c["passed"])
            self.checks_failed = sum(1 for c in result["checks"] if not c["passed"])
            
            result["active_content_free"] = all(
                c["passed"] for c in result["checks"] 
                if c["name"] in ["javascript_objects", "embedded_files", "automatic_actions"]
            )
            
            result["structurally_valid"] = all(
                c["passed"] for c in result["checks"]
                if c["name"] in ["pdf_header", "xref_structure"]
            )
            
            result["overall_status"] = "PASSED" if self.checks_failed == 0 else "FAILED"
            
        except Exception as e:
            result["overall_status"] = "ERROR"
            result["checks"].append({
                "name": "fatal_error",
                "passed": False,
                "detail": str(e)
            })
        
        return result
    
    def _check_pdf_header(self, content: bytes) -> Dict[str, Any]:
        passed = content.startswith(b'%PDF-')
        return {
            "name": "pdf_header",
            "passed": passed,
            "detail": "Valid PDF header" if passed else "Missing or invalid PDF header"
        }
    
    def _check_javascript_objects(self, content: bytes) -> Dict[str, Any]:
        js_objects = [
            b'/JavaScript', b'/JS',
            b'eval(', b'unescape(',
            b'String.fromCharCode', b'ActiveXObject'
        ]
        
        found = []
        for obj in js_objects:
            if obj in content:
                found.append(obj.decode('ascii', errors='replace'))
        
        return {
            "name": "javascript_objects",
            "passed": len(found) == 0,
            "detail": "No JavaScript objects found" if len(found) == 0 else f"Found: {', '.join(found)}"
        }
    
    def _check_embedded_files(self, content: bytes) -> Dict[str, Any]:
        embedded_indicators = [
            b'/EmbeddedFile', b'/EmbeddedFiles',
            b'MZ', b'\x7fELF'
        ]
        
        found = []
        for indicator in embedded_indicators:
            if indicator in content:
                found.append(indicator.decode('ascii', errors='replace'))
        
        return {
            "name": "embedded_files",
            "passed": len(found) == 0,
            "detail": "No embedded files" if len(found) == 0 else f"Found indicators: {', '.join(found)}"
        }
    
    def _check_automatic_actions(self, content: bytes) -> Dict[str, Any]:
        actions = [b'/OpenAction', b'/AA', b'/Launch']
        
        found = []
        for action in actions:
            if action in content:
                found.append(action.decode('ascii', errors='replace'))
        
        return {
            "name": "automatic_actions",
            "passed": len(found) == 0,
            "detail": "No automatic actions" if len(found) == 0 else f"Found: {', '.join(found)}"
        }
    
    def _check_dangerous_filters(self, content: bytes) -> Dict[str, Any]:
        filters = [
            b'/ASCIIHexDecode', b'/ASCII85Decode',
            b'/Crypt', b'/LZWDecode'
        ]
        
        found = []
        for filt in filters:
            if filt in content:
                found.append(filt.decode('ascii', errors='replace'))
        
        return {
            "name": "dangerous_filters",
            "passed": len(found) == 0,
            "detail": "No dangerous filters" if len(found) == 0 else f"Found: {', '.join(found)}"
        }
    
    def _check_xref_structure(self, content: bytes) -> Dict[str, Any]:
        has_xref = b'xref' in content
        has_xref_stream = b'/XRef' in content
        has_trailer = b'trailer' in content
        has_startxref = b'startxref' in content
        has_eof = content.rstrip().endswith(b'%%EOF')
        
        valid = (has_xref or has_xref_stream) and has_trailer and has_eof
        
        return {
            "name": "xref_structure",
            "passed": valid,
            "detail": "Valid cross-reference structure" if valid else "Missing xref/trailer/EOF markers"
        }

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='DocCore Second Pass Verification')
    parser.add_argument('--file', required=True, help='Sanitized file to verify')
    
    args = parser.parse_args()
    
    verifier = SecondPassVerifier()
    
    extension = os.path.splitext(args.file)[1].lower()
    
    if extension == '.pdf':
        result = verifier.verify_pdf_complete(args.file)
    else:
        result = {
            "format": extension,
            "overall_status": "UNSUPPORTED",
            "checks": [{"name": "format_check", "passed": False, "detail": f"Format {extension} not supported for verification"}]
        }
    
    print(json.dumps(result, indent=2, ensure_ascii=False))
