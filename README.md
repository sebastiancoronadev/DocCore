<div align="center">

# 📄 DocCore · 核文

### Multi-Layer Document Analysis Engine · Enterprise Data Security

[![Website](https://img.shields.io/badge/Website-codexstudiove.com-0A0A0A?style=for-the-badge&logo=vercel&logoColor=white)](https://www.codexstudiove.com)
[![GitHub](https://img.shields.io/badge/GitHub-@sebastiancoronadev-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sebastiancoronadev)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/sebastiancoronadev)
[![Email](https://img.shields.io/badge/Email-sebastiancorona@codexstudiove.com-EA4335?style=for-the-badge&logo=gmail&logoColor=white)](mailto:sebastiancorona@codexstudiove.com)

---

### Created by:

<h1>@sebastiancoronadev&nbsp;<sub><a href="https://github.com/sebastiancoronadev" target="_blank" title="Verified"><img src="https://i.ibb.co/1F3qqjd/verified.gif" width="30"></a></sub></h1>

<h1>@liangzhaodev&nbsp;<sub><a href="https://github.com/liangzhaodev" target="_blank" title="Verified"><img src="https://i.ibb.co/1F3qqjd/verified.gif" width="30"></a></sub></h1>

**Lead Security Architects** · [codexstudiove.com](https://www.codexstudiove.com)

---

**Huizhiyun Technologies Inc. · 汇智云科技股份有限公司 · Enterprise Data Solutions**

---

</div>

---

# 🇨🇳 中文

## 📋 项目概述

**DocCore (核文)** 是一个多层文档分析引擎，完全在内存中运行，不依赖外部数据库或图形界面。每个模块都使用最适合其特定功能的语言编写，优先考虑性能和准确性，而非技术同质性。

执行流程遵循集中编排模式，PowerShell 充当协调大脑，根据文件类型和请求的分析深度调用 Rust、Python、C++ 和 Node.js 中的专业模块。所有模块通过 stdout 使用 JSON 进行通信，允许替换任何组件而不影响系统的其余部分。

---

## 🏗️ 系统架构

```
┌────────────────────────────────────────────────────────────────────────────┐
│                      DOCORE ORCHESTRATOR                                   │
│                         PowerShell                                         │
├────────────────────────────────────────────────────────────────────────────┤ 
│                                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │    Rust      │  │   Python     │  │    C++       │  │   Node.js    │    │
│  │  Binary      │  │  Document    │  │  Memory      │  │   Script     │    │
│  │  Scanner     │  │  Analyzer    │  │  Handler     │  │   Analyzer   │    │
│  │  Parallel    │  │  PDF Parser  │  │  Buffer      │  │   Static     │    │
│  │  YARA        │  │  Metadata    │  │  Operations  │  │   Detection  │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│         │                 │                 │                 │            │
│         └─────────────────┼─────────────────┼─────────────────┘            │
│                           │                 │                              │
│                    ┌──────▼─────────────────▼───────┐                      │
│                    │      JSON Report Output        │                      │
│                    │        Threat Level            │                      │
│                    │    Suspicious Patterns         │                      │
│                    └────────────────────────────────┘                      │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ 技术栈

<div align="center">

<!-- CORE LANGUAGES -->
<a href="https://www.google.com/search?q=PowerShell+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=powershell" title="PowerShell - Orchestrator" />
</a>
<a href="https://www.google.com/search?q=Rust+programming+language+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=rust" title="Rust - Binary Scanner" />
</a>
<a href="https://www.google.com/search?q=Python+programming+language+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=python" title="Python - Document Analyzer" />
</a>
<a href="https://www.google.com/search?q=C+++programming+language+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=cpp" title="C++ - Memory Handler" />
</a>
<a href="https://www.google.com/search?q=Node.js+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=nodejs" title="Node.js - Script Analyzer" />
</a>
<br>

<!-- TOOLS -->
<a href="https://www.google.com/search?q=Git+version+control+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=git" title="Git - Version Control" />
</a>
<a href="https://www.google.com/search?q=GitHub+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=github" title="GitHub - Repository Hosting" />
</a>

</div>

| 模块 | 语言 | 功能 |
|------|------|------|
| **编排器** | PowerShell | 协调、文件检测、威胁聚合 |
| **二进制扫描器** | Rust | 并行 YARA、哈希、熵分析 |
| **文档分析器** | Python | PDF 解析、元数据提取、JavaScript 检测 |
| **内存处理器** | C++ | 缓冲区操作、负载提取 |
| **脚本分析器** | Node.js | 静态代码分析、混淆检测 |

---

## 🔧 模块详解

### PowerShell 编排器

编排器管理每个分析的完整生命周期。调用 `Start-DocCoreScan` 时，会创建一个带有唯一标识符的隔离会话，封装所有结果。此会话不会持久化到磁盘，确保每次分析都是独立的且不留下痕迹。

**Magic Bytes 识别：** 检查文件的前八个字节以识别实际格式，忽略文件扩展名。识别的 Magic Bytes 包括 PDF、OLE2、Office Open XML、PE 可执行文件、ELF 二进制和 Mach-O。

**香农熵计算：** 分析文件中每个字节的频率分布。熵值高于 0.85 表示加密或压缩内容，低于 0.40 表示纯文本或源代码。

**威胁等级聚合：** YARA 模式检测贡献最多 40 分，高熵贡献 30 分，可疑流贡献 20 分。阈值：70+ = 严重，40-69 = 高，<40 = 低。

---

### Rust 二进制扫描器

利用 Rayon 库的并发能力，在所有可用 CPU 核心上自动分配工作。使用内存映射文件避免将完整文件加载到内存中，允许分析任何大小的文档，RAM 消耗恒定。

**并行哈希计算：** SHA-256、SHA-512 和 MD5 在单独的线程中同时计算。对于大文件，扫描器将数据分块并独立处理每个块，在现代化硬件上达到高达 1.5 GB/s 的处理速度。

**YARA 模式检测：** 在 Rust 中直接实现 YARA 语言子集。模式包括已知恶意软件签名如 PE 头、NOP sled shellcode、Base64 编码的 PowerShell 命令和 JavaScript 混淆模式。

**分区分析：** 将文件分割成 4096 字节块并计算每个块的局部熵。熵值高于 0.90 的区域标记为高度可疑。

---

### Python 文档分析器

实现 PDF 解析器，遍历文件内部结构以查找可疑对象。检查每个压缩流，使用 zlib 解压并分析其内容，寻找嵌入的 JavaScript、危险 API 调用和混淆模式。

**JavaScript 提取：** 使用专门的 regex 搜索 `/JavaScript`、`/JS`、`eval()`、`unescape()`、`String.fromCharCode` 和 `ActiveXObject` 等对象。

**元数据提取：** 提取作者、创建者、生产者、创建和修改日期。支持多种 PDF 字符串编码：UTF-8、UTF-16 Big Endian、UTF-16 Little Endian 和 ASCII。

**中文编码检测：** 在 0xE4-0xE9 范围内寻找多字节 UTF-8 字节序列，这是中文、日文和韩文字符的特征。

---

### C++ 内存处理器

直接在文件的二进制缓冲区上操作，允许在解释型语言中效率低下的低级操作。使用直接指针和地址算术以获得最大速度。

**元数据删除：** 逐字节遍历文件，识别标准 PDF 元数据键并将其从缓冲区中删除。

**Payload 提取：** 搜索嵌入可执行文件的二进制签名：MZ 头（PE）、0x7F454C46（ELF）和 0xCAFEBABE（Mach-O）。还使用 256 字节滑动窗口以 50% 重叠识别可能包含 shellcode 的高熵区域。

---

### Node.js 脚本分析器

将文件内容作为文本进行静态分析，搜索恶意代码模式，无论容器格式如何。即使它们位于 Python 模块已提取的压缩流中，也能检测 VBA 宏、嵌入脚本和 JavaScript 代码。

**可疑函数检测：** 维护包括 `eval()`、`ActiveXObject`、`WScript.Shell` 和 `String.fromCharCode` 等模式的数据库。

**混淆评分：** 评估平均行长度（过长的行表示压缩或混淆代码）、特殊字符比例（正常代码以字母数字为主）和长 Base64 字符串数量（常用于隐藏 payloads）。

**风险评估：** 结合混淆检测、可疑函数计数和文本内容的熵以产生最终分类。

---

## 🛡️ 安全设计原则

| 原则 | 描述 |
|------|------|
| **离线模式** | 信息不会离开系统 |
| **零数据库** | 消除攻击面 |
| **仅内存处理** | 磁盘上不留痕迹 |
| **会话隔离** | 防止分析之间的交叉污染 |
| **模块独立性** | 每个模块都可替换 |
| **JSON 通信** | 最简单的通用协议 |

---

## 🚀 使用方式

```powershell
# 基本分析
Start-DocCoreScan -FilePath "document.pdf"

# 深度扫描
Start-DocCoreScan -FilePath "document.pdf" -DeepScan

# 剥离元数据
Start-DocCoreScan -FilePath "document.pdf" -StripMetadata

# 提取 Payloads
Start-DocCoreScan -FilePath "document.pdf" -ExtractPayloads
```

---

## 📄 许可证

版权所有 © 2026 **Huizhiyun Technologies Inc.** · **汇智云科技股份有限公司**

All Rights Reserved · 保留所有权利

---

---

# 🇺🇸 ENGLISH

## 📋 Project Overview

**DocCore (核文)** is a multi-layer document analysis engine that operates entirely in memory, without relying on external databases or graphical interfaces. Each module is written in the language best suited for its specific function, prioritizing performance and accuracy over technological homogeneity.

The execution flow follows a centralized orchestration pattern where PowerShell acts as the coordinating brain, invoking specialized modules in Rust, Python, C++, and Node.js based on the file type and requested analysis depth. All modules communicate via JSON through stdout, allowing any component to be replaced without affecting the rest of the system.

---

## 🏗️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                      DOCORE ORCHESTRATOR                                   │
│                         PowerShell                                         │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │    Rust      │  │   Python     │  │    C++       │  │   Node.js    │    │
│  │  Binary      │  │  Document    │  │  Memory      │  │   Script     │    │
│  │  Scanner     │  │  Analyzer    │  │  Handler     │  │   Analyzer   │    │
│  │  Parallel    │  │  PDF Parser  │  │  Buffer      │  │   Static     │    │
│  │  YARA        │  │  Metadata    │  │  Operations  │  │   Detection  │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│         │                 │                 │                 │            │
│         └─────────────────┼─────────────────┼─────────────────┘            │
│                           │                 │                              │
│                    ┌──────▼─────────────────▼───────┐                      │
│                    │      JSON Report Output        │                      │
│                    │        Threat Level            │                      │
│                    │    Suspicious Patterns         │                      │
│                    └────────────────────────────────┘                      │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Technology Stack

<div align="center">

<!-- CORE LANGUAGES -->
<a href="https://www.google.com/search?q=PowerShell+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=powershell" title="PowerShell - Orchestrator" />
</a>
<a href="https://www.google.com/search?q=Rust+programming+language+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=rust" title="Rust - Binary Scanner" />
</a>
<a href="https://www.google.com/search?q=Python+programming+language+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=python" title="Python - Document Analyzer" />
</a>
<a href="https://www.google.com/search?q=C+++programming+language+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=cpp" title="C++ - Memory Handler" />
</a>
<a href="https://www.google.com/search?q=Node.js+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=nodejs" title="Node.js - Script Analyzer" />
</a>
<br>

<!-- TOOLS -->
<a href="https://www.google.com/search?q=Git+version+control+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=git" title="Git - Version Control" />
</a>
<a href="https://www.google.com/search?q=GitHub+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=github" title="GitHub - Repository Hosting" />
</a>

</div>

| Module | Language | Function |
|--------|----------|----------|
| **Orchestrator** | PowerShell | Coordination, file detection, threat aggregation |
| **Binary Scanner** | Rust | Parallel YARA, hashing, entropy analysis |
| **Document Analyzer** | Python | PDF parsing, metadata extraction, JavaScript detection |
| **Memory Handler** | C++ | Buffer operations, payload extraction |
| **Script Analyzer** | Node.js | Static code analysis, obfuscation detection |

---

## 🔧 Module Details

### PowerShell Orchestrator

The orchestrator manages the complete lifecycle of each analysis. When `Start-DocCoreScan` is invoked, an isolated session with a unique identifier is created that encapsulates all results. This session does not persist to disk, ensuring each analysis is independent and leaves no traces.

**Magic Bytes Identification:** Examines the first eight bytes of the file to identify the actual format, ignoring the extension. Recognized magic bytes include PDF, OLE2, Office Open XML, PE executable, ELF binary, and Mach-O.

**Shannon Entropy Calculation:** Analyzes the frequency distribution of each byte in the file. Entropy above 0.85 suggests encrypted or compressed content, while values below 0.40 indicate plaintext or source code.

**Threat Level Aggregation:** YARA pattern detection contributes up to 40 points, high entropy adds 30 points, and suspicious streams add 20 points. Threshold: 70+ = Critical, 40-69 = High, <40 = Low.

---

### Rust Binary Scanner

Leverages Rayon library's concurrency capabilities to automatically distribute work across all available CPU cores. Uses memory-mapped files to avoid loading entire files into memory, allowing analysis of documents of any size with constant RAM consumption.

**Parallel Hash Computation:** SHA-256, SHA-512, and MD5 are computed simultaneously in separate threads. For large files, the scanner divides data into chunks and processes each independently, achieving processing speeds of up to 1.5 GB/s on modern hardware.

**YARA Pattern Detection:** Implements a subset of the YARA language directly in Rust. Patterns include known malware signatures such as PE headers, NOP sled shellcode, Base64-encoded PowerShell commands, and JavaScript obfuscation patterns.

**Section Analysis:** Divides the file into 4096-byte blocks and calculates local entropy for each. Regions with entropy above 0.90 are marked as highly suspicious.

---

### Python Document Analyzer

Implements a PDF parser that traverses the file's internal structure looking for suspicious objects. Examines each compressed stream, decompresses it with zlib, and analyzes its content for embedded JavaScript, dangerous API calls, and obfuscation patterns.

**JavaScript Extraction:** Uses specialized regex to search for objects like `/JavaScript`, `/JS`, `eval()`, `unescape()`, `String.fromCharCode`, and `ActiveXObject`.

**Metadata Extraction:** Extracts author, creator, producer, creation and modification dates. Supports multiple PDF string encodings: UTF-8, UTF-16 Big Endian, UTF-16 Little Endian, and ASCII.

**Chinese Encoding Detection:** Looks for multi-byte UTF-8 byte sequences in the 0xE4-0xE9 range, characteristic of Chinese, Japanese, and Korean characters.

---

### C++ Memory Handler

Operates directly on the file's binary buffers, enabling low-level operations that would be inefficient in interpreted languages. Uses direct pointers and address arithmetic for maximum speed.

**Metadata Removal:** Traverses the file byte by byte, identifying standard PDF metadata keys and removing them from the buffer.

**Payload Extraction:** Searches for binary signatures of embedded executables: MZ headers (PE), 0x7F454C46 (ELF), and 0xCAFEBABE (Mach-O). Also identifies high-entropy regions that may contain shellcode using a 256-byte sliding window with 50% overlap.

---

### Node.js Script Analyzer

Performs static analysis of file content as text, searching for malicious code patterns regardless of container format. Detects VBA macros, embedded scripts, and JavaScript code even when inside compressed streams already extracted by the Python module.

**Suspicious Function Detection:** Maintains a pattern database including `eval()`, `ActiveXObject`, `WScript.Shell`, and `String.fromCharCode`.

**Obfuscation Scoring:** Evaluates average line length (excessively long lines suggest minified or obfuscated code), special character ratio (normal code is predominantly alphanumeric), and number of long Base64 strings (commonly used to hide payloads).

**Risk Assessment:** Combines obfuscation detection, suspicious function count, and text content entropy to produce a final classification.

---

## 🛡️ Security Design Principles

| Principle | Description |
|-----------|-------------|
| **Offline Mode** | No information leaves the system |
| **Zero Database** | Eliminates attack surfaces |
| **Memory-Only Processing** | No traces left on disk |
| **Session Isolation** | Prevents cross-contamination between analyses |
| **Module Independence** | Each module is replaceable |
| **JSON Communication** | Simplest universal protocol |

---

## 🚀 Usage

```powershell
# Basic analysis
Start-DocCoreScan -FilePath "document.pdf"

# Deep scan
Start-DocCoreScan -FilePath "document.pdf" -DeepScan

# Strip metadata
Start-DocCoreScan -FilePath "document.pdf" -StripMetadata

# Extract payloads
Start-DocCoreScan -FilePath "document.pdf" -ExtractPayloads
```

---

## 📄 License

Copyright © 2026 **Huizhiyun Technologies Inc.** · **汇智云科技股份有限公司**

All Rights Reserved

---

---

# 🇪🇸 ESPAÑOL

## 📋 Descripción del Proyecto

**DocCore (核文)** es un motor de análisis documental multicapa que opera completamente en memoria, sin depender de bases de datos externas ni interfaces gráficas. Cada módulo está escrito en el lenguaje más adecuado para su función específica, priorizando el rendimiento y la precisión sobre la homogeneidad tecnológica.

El flujo de ejecución sigue un patrón de orquestación centralizada donde PowerShell actúa como cerebro coordinador, invocando módulos especializados en Rust, Python, C++ y Node.js según el tipo de archivo y la profundidad de análisis solicitada. Todos los módulos se comunican mediante JSON a través de stdout, lo que permite reemplazar cualquier componente sin afectar al resto del sistema.

---

## 🏗️ Arquitectura del Sistema

```
┌────────────────────────────────────────────────────────────────────────────┐
│                      DOCORE ORCHESTRATOR                                   │
│                         PowerShell                                         │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │    Rust      │  │   Python     │  │    C++       │  │   Node.js    │    │
│  │  Binary      │  │  Document    │  │  Memory      │  │   Script     │    │
│  │  Scanner     │  │  Analyzer    │  │  Handler     │  │   Analyzer   │    │
│  │  Parallel    │  │  PDF Parser  │  │  Buffer      │  │   Static     │    │
│  │  YARA        │  │  Metadata    │  │  Operations  │  │   Detection  │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│         │                 │                 │                 │            │
│         └─────────────────┼─────────────────┼─────────────────┘            │
│                           │                 │                              │
│                    ┌──────▼─────────────────▼───────┐                      │
│                    │      JSON Report Output        │                      │
│                    │        Threat Level            │                      │
│                    │    Suspicious Patterns         │                      │
│                    └────────────────────────────────┘                      │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Stack Tecnológico

<div align="center">

<!-- CORE LANGUAGES -->
<a href="https://www.google.com/search?q=PowerShell+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=powershell" title="PowerShell - Orquestador" />
</a>
<a href="https://www.google.com/search?q=Rust+programming+language+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=rust" title="Rust - Escáner Binario" />
</a>
<a href="https://www.google.com/search?q=Python+programming+language+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=python" title="Python - Analizador de Documentos" />
</a>
<a href="https://www.google.com/search?q=C+++programming+language+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=cpp" title="C++ - Manejador de Memoria" />
</a>
<a href="https://www.google.com/search?q=Node.js+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=nodejs" title="Node.js - Analizador de Scripts" />
</a>
<br>

<!-- TOOLS -->
<a href="https://www.google.com/search?q=Git+version+control+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=git" title="Git - Control de Versiones" />
</a>
<a href="https://www.google.com/search?q=GitHub+explanation" target="_blank" style="cursor: pointer;">
  <img src="https://skillicons.dev/icons?i=github" title="GitHub - Alojamiento del Repositorio" />
</a>

</div>

| Módulo | Lenguaje | Función |
|--------|----------|---------|
| **Orquestador** | PowerShell | Coordinación, detección de archivos, agregación de amenazas |
| **Escáner Binario** | Rust | YARA paralelo, hashing, análisis de entropía |
| **Analizador de Documentos** | Python | Parsing PDF, extracción de metadatos, detección de JavaScript |
| **Manejador de Memoria** | C++ | Operaciones de buffer, extracción de payloads |
| **Analizador de Scripts** | Node.js | Análisis estático de código, detección de ofuscación |

---

## 🔧 Detalles de Módulos

### Orquestador PowerShell

El orquestador gestiona el ciclo de vida completo de cada análisis. Cuando se invoca `Start-DocCoreScan`, se crea una sesión aislada con identificador único que encapsula todos los resultados. Esta sesión no persiste en disco, garantizando que cada análisis sea independiente y no deje rastros.

**Identificación por Magic Bytes:** Examina los primeros ocho bytes del archivo para identificar el formato real, ignorando la extensión. Los magic bytes reconocidos incluyen PDF, OLE2, Office Open XML, PE ejecutable, ELF binario y Mach-O.

**Cálculo de Entropía de Shannon:** Analiza la distribución de frecuencias de cada byte en el archivo. Una entropía superior a 0.85 sugiere contenido cifrado o comprimido, mientras que valores por debajo de 0.40 indican texto plano o código fuente.

**Agregación de Nivel de Amenaza:** La detección de patrones YARA aporta hasta 40 puntos, la entropía alta suma 30 puntos, y los streams sospechosos añaden 20 puntos. Umbrales: 70+ = Crítico, 40-69 = Alto, <40 = Bajo.

---

### Escáner Binario Rust

Aprovecha las capacidades de concurrencia de la biblioteca Rayon para distribuir automáticamente el trabajo entre todos los núcleos disponibles del procesador. Utiliza memory-mapped files para evitar cargar archivos completos en memoria, permitiendo analizar documentos de cualquier tamaño con un consumo constante de RAM.

**Cálculo Paralelo de Hashes:** SHA-256, SHA-512 y MD5 se computan simultáneamente en hilos separados. Para archivos grandes, el escáner divide los datos en chunks y procesa cada uno de forma independiente, alcanzando velocidades de hasta 1.5 GB/s en hardware moderno.

**Detección de Patrones YARA:** Implementa un subconjunto del lenguaje YARA directamente en Rust. Los patrones incluyen firmas de malware conocidas como cabeceras PE, secuencias NOP sled de shellcode, comandos PowerShell codificados en Base64 y patrones de ofuscación JavaScript.

**Análisis de Secciones:** Divide el archivo en bloques de 4096 bytes y calcula la entropía local de cada uno. Las regiones con entropía superior a 0.90 se marcan como altamente sospechosas.

---

### Analizador de Documentos Python

Implementa un parser de PDF que recorre la estructura interna del archivo en busca de objetos sospechosos. Examina cada stream comprimido, lo descomprime con zlib y analiza su contenido en busca de JavaScript embebido, llamadas a APIs peligrosas y patrones de ofuscación.

**Extracción de JavaScript:** Utiliza expresiones regulares especializadas que buscan objetos como `/JavaScript`, `/JS`, `eval()`, `unescape()`, `String.fromCharCode` y `ActiveXObject`.

**Extracción de Metadatos:** Extrae información como autor, creador, productor, fechas de creación y modificación. Implementa decodificación de cadenas PDF en múltiples formatos: UTF-8, UTF-16 Big Endian, UTF-16 Little Endian y ASCII.

**Detección de Codificación China:** Busca secuencias de bytes UTF-8 multi-byte en el rango 0xE4-0xE9, características de caracteres chinos, japoneses y coreanos.

---

### Manejador de Memoria C++

Opera directamente sobre los buffers binarios del archivo, permitiendo operaciones de bajo nivel que serían ineficientes en lenguajes interpretados. Utiliza punteros directos y aritmética de direcciones para máxima velocidad.

**Eliminación de Metadatos:** Recorre el archivo byte por byte identificando claves de metadatos PDF estándar y eliminándolas del buffer.

**Extracción de Payloads:** Busca firmas binarias de ejecutables embebidos: cabeceras MZ para PE, 0x7F454C46 para ELF, y 0xCAFEBABE para Mach-O. También identifica regiones de alta entropía local que podrían contener shellcode, utilizando una ventana deslizante de 256 bytes con solapamiento del 50%.

---

### Analizador de Scripts Node.js

Examina el contenido del archivo como texto, buscando patrones de código malicioso independientemente del formato contenedor. Permite detectar macros VBA, scripts embebidos y código JavaScript incluso cuando están dentro de streams comprimidos que ya fueron extraídos por el módulo Python.

**Detección de Funciones Sospechosas:** Mantiene una base de datos de patrones que incluye `eval()`, `ActiveXObject`, `WScript.Shell` y `String.fromCharCode`.

**Puntuación de Ofuscación:** Evalúa tres factores: longitud promedio de línea (líneas excesivamente largas sugieren código minificado u ofuscado), proporción de caracteres especiales (el código normal tiene predominancia alfanumérica), y cantidad de cadenas Base64 largas (comúnmente usadas para ocultar payloads).

**Evaluación de Riesgo:** Combina la detección de ofuscación, el conteo de funciones sospechosas y la entropía del contenido textual para producir una clasificación final.

---

## 🛡️ Principios de Diseño de Seguridad

| Principio | Descripción |
|-----------|-------------|
| **Modo Offline** | Ninguna información sale del sistema |
| **Cero Bases de Datos** | Elimina superficies de ataque |
| **Procesamiento en Memoria** | No deja rastros en disco |
| **Aislamiento de Sesiones** | Previene contaminación cruzada entre análisis |
| **Independencia de Módulos** | Cada módulo es reemplazable |
| **Comunicación JSON** | Protocolo universal más simple |

---

## 🚀 Uso

```powershell
# Análisis básico
Start-DocCoreScan -FilePath "document.pdf"

# Escaneo profundo
Start-DocCoreScan -FilePath "document.pdf" -DeepScan

# Eliminar metadatos
Start-DocCoreScan -FilePath "document.pdf" -StripMetadata

# Extraer payloads
Start-DocCoreScan -FilePath "document.pdf" -ExtractPayloads
```

---

## 📄 Licencia

Copyright © 2026 **Huizhiyun Technologies Inc.** · **汇智云科技股份有限公司**

Todos los derechos reservados · All Rights Reserved

---

<div align="center">

**⭐ If you like this project, give it a star on GitHub!** 💜  
**⭐ 如果喜欢这个项目，请在 GitHub 上给它一颗星！** 💜  
**⭐ ¡Si te gusta este proyecto, dale una estrella en GitHub!** 💜

</div>

---

**Released with 💜 by Sebastián Corona & Liang Zhao**  
*Engineering enterprise-grade document security solutions.*