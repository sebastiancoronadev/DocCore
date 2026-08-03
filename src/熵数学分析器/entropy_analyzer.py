import math, json, hashlib
from typing import Dict, List, Tuple

class 熵数学分析器:
    @staticmethod
    def 完整分析(file_path: str) -> Dict:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        length = len(data)
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        
        ent = 0.0
        inv = 1.0 / length
        for f in freq:
            if f:
                p = f * inv
                ent -= p * math.log2(p)
        香农 = ent / 8.0
        
        expected = length / 256
        chi2 = sum(((f - expected) ** 2) / expected for f in freq)
        
        if length > 1:
            mean = sum(data) / length
            n = length - 1
            num = sum((data[i] - mean) * (data[i + 1] - mean) for i in range(n))
            den = sum((b - mean) ** 2 for b in data)
            correl = num / den if den != 0 else 0.0
        else:
            correl = 0.0
        
        samples = min(10000, length // 2)
        inside = 0
        for i in range(0, samples * 2, 2):
            if i + 1 < length:
                x = data[i] / 255.0
                y = data[i + 1] / 255.0
                if x * x + y * y <= 1.0:
                    inside += 1
        monte_carlo = (4.0 * inside) / samples if samples > 0 else 0.0
        
        opcodes = [
            bytes([0x55, 0x48, 0x89, 0xe5]),
            bytes([0x48, 0x83, 0xec]),
            bytes([0xe8]),
            bytes([0xff, 0x15]),
            bytes([0x0f, 0x05]),
            bytes([0xcd, 0x80]),
        ]
        has_opcodes = any(op in data for op in opcodes)
        
        apis = [
            b'CreateProcess', b'VirtualAlloc', b'WriteProcessMemory',
            b'CreateRemoteThread', b'GetProcAddress', b'socket', b'connect'
        ]
        has_api = any(api in data for api in apis)
        
        nop_count = data.count(b'\x90')
        nop_ratio = nop_count / length if length > 0 else 0
        
        shellcode_score = 0
        if 香农 > 0.80: shellcode_score += 30
        if 香农 > 0.90: shellcode_score += 25
        if nop_ratio > 0.3: shellcode_score += 25
        if shellcode_score >= 55: 是Shellcode = True
        else: 是Shellcode = False
        
        if 香农 > 0.85 and has_opcodes: 是恶意 = True
        elif 香农 > 0.80 and has_api: 是恶意 = True
        elif chi2 > 500 and has_opcodes: 是恶意 = True
        else: 是恶意 = False
        
        威胁 = "恶意" if 是恶意 or 是Shellcode else "安全"
        
        return {
            "文件名": file_path.split("\\")[-1] if "\\" in file_path else file_path.split("/")[-1],
            "文件大小": length,
            "SHA256": hashlib.sha256(data).hexdigest()[:32],
            "熵分析": {
                "香农熵": round(香农, 6),
                "卡方检验": round(chi2, 2),
                "序列相关": round(correl, 6),
                "蒙特卡洛π逼近": round(monte_carlo, 6)
            },
            "恶意软件检测": {
                "可执行代码": 是恶意,
                "Shellcode": 是Shellcode,
                "NOP滑板比例": round(nop_ratio, 4)
            },
            "威胁级别": 威胁,
            "分析时间": "即时"
        }

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description='熵数学分析器')
    p.add_argument('--file', required=True, help='要分析的文件')
    a = p.parse_args()
    print(json.dumps(熵数学分析器.完整分析(a.file), indent=2, ensure_ascii=False))
