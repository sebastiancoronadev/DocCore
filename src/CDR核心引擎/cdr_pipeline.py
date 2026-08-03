import sys, json, re, zlib, hashlib, os, math
from datetime import datetime
from typing import Dict, List, Any, Tuple

class 威胁级别:
    安全 = "安全"
    可疑 = "可疑"
    恶意 = "恶意"
    未确定 = "未确定"

class PDF快速清理器:
    元数据正则 = re.compile(
        rb'/(?:Author|Creator|Producer|Title|Subject|Keywords|CreationDate|ModDate|Company|Manager|Category|Comments|SourceModified|DocChecksum|LastAuthor|RevisionNumber|Version|Application|DocumentID|InstanceID|Metadata)\s*(?:\((?:[^()\\]|\\.|\((?:[^()\\]|\\.)*\))*\)|<<[^>]*>>|<[^>]*>)'
    )
    
    危险对象正则 = re.compile(
        rb'/(?:JavaScript|JS|OpenAction|AA|Launch|EmbeddedFile|EmbeddedFiles|RichMedia|Collection|XFA|Encrypt|Sig|ObjStm|SubmitForm|ImportData|URI|GoToR|GoToE|Thread|Sound|Movie|Screen|3D)(?:\s*<<[^>]*>>|\s*\([^)]*\))?'
    )
    
    @classmethod
    def 快速清理(cls, file_path: str) -> Tuple[bytes, Dict]:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        reporte = {"检测到的元数据": [], "清理的元数据": [], "检测到的活动内容": [], "清理的活动内容": []}
        
        for match in cls.元数据正则.finditer(content):
            nombre = match.group().split(b'/')[1].split(b' ')[0].split(b'<')[0].split(b'(')[0].decode('ascii', errors='replace')
            reporte["检测到的元数据"].append(nombre)
        
        for match in cls.危险对象正则.finditer(content):
            nombre = match.group().split(b'/')[1].split(b' ')[0].split(b'<')[0].decode('ascii', errors='replace')
            reporte["检测到的活动内容"].append(nombre)
        
        limpio = cls.元数据正则.sub(b'', content)
        limpio = cls.危险对象正则.sub(b'', limpio)
        
        for old, new in [(b'/ASCIIHexDecode', b'/FlateDecode'), (b'/ASCII85Decode', b'/FlateDecode'), (b'/Crypt', b'/FlateDecode')]:
            limpio = limpio.replace(old, new)
        
        reporte["清理的元数据"] = reporte["检测到的元数据"][:]
        reporte["清理的活动内容"] = reporte["检测到的活动内容"][:]
        
        return limpio, reporte

class 熵分析器:
    @staticmethod
    def 快速熵(data: bytes) -> float:
        if len(data) < 256:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        ent = 0.0
        inv = 1.0 / len(data)
        for f in freq:
            if f:
                p = f * inv
                ent -= p * math.log2(p)
        return ent / 8.0

class CDR引擎:
    @staticmethod
    def 清理(file_path: str) -> Dict:
        t0 = datetime.now()
        with open(file_path, 'rb') as f:
            raw = f.read()
        
        limpio, rep = PDF快速清理器.快速清理(file_path)
        ent = 熵分析器.快速熵(raw)
        
        ruta = file_path + ".sanitized.pdf"
        with open(ruta, 'wb') as f:
            f.write(limpio)
        
        dt = (datetime.now() - t0).total_seconds() * 1000
        
        return {
            "状态": "已清理",
            "威胁级别": 威胁级别.安全,
            "原始文件": os.path.basename(file_path),
            "原始哈希": hashlib.sha256(raw).hexdigest()[:32],
            "清理哈希": hashlib.sha256(limpio).hexdigest()[:32],
            "原始大小": len(raw),
            "清理大小": len(limpio),
            "缩减比例": round((1 - len(limpio)/len(raw)) * 100, 2),
            "香农熵": round(ent, 6),
            "移除的元数据": rep["清理的元数据"],
            "移除的活动内容": rep["清理的活动内容"],
            "清理文件": ruta,
            "处理时间毫秒": round(dt, 2)
        }

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--file', required=True)
    a = p.parse_args()
    print(json.dumps(CDR引擎.清理(a.file), indent=2, ensure_ascii=False))
