using namespace System.Management.Automation
using namespace System.Security.Cryptography
using namespace System.IO
using namespace System.Text
using namespace System.Collections.Concurrent

class DocCoreSession {
    [string]$SessionId
    [datetime]$StartTime
    [hashtable]$AnalysisResults
    [ConcurrentBag[object]]$ThreatFindings
    
    DocCoreSession() {
        $this.SessionId = [Guid]::NewGuid().ToString()
        $this.StartTime = [datetime]::Now
        $this.AnalysisResults = @{}
        $this.ThreatFindings = [ConcurrentBag[object]]::new()
    }
}

class DocumentFingerprint {
    [string]$SHA256
    [string]$SHA512
    [string]$MD5
    [string]$EntropyScore
    [int]$FileSize
    [string]$MagicBytes
    [hashtable]$StructuralAnomalies
}

class ThreatIndicator {
    [string]$IndicatorType
    [string]$Severity
    [string]$Description
    [string]$Location
    [byte[]]$PayloadSample
    [double]$ConfidenceScore
}

function Get-MagicBytesIdentification {
    param([byte[]]$FileHeader)
    
    $magicSignatures = @{
        '25504446' = 'PDF Document'
        'D0CF11E0' = 'OLE2 Compound Document (Office 97-2003)'
        '504B0304' = 'Office Open XML (2007+)'
        '4D5A' = 'PE Executable'
        '7F454C46' = 'ELF Binary'
        'CAFEBABE' = 'Java Class File / Mach-O Universal Binary'
    }
    
    $hexSignature = [BitConverter]::ToString($FileHeader[0..7]) -replace '-',''
    
    foreach ($signature in $magicSignatures.Keys) {
        if ($hexSignature.StartsWith($signature)) {
            return $magicSignatures[$signature]
        }
    }
    
    return "Unknown Binary Format"
}

function Invoke-ShannonEntropyCalculation {
    param([byte[]]$Data)
    
    $entropy = 0.0
    $length = $Data.Length
    $frequencies = @{}
    
    foreach ($byte in $Data) {
        $frequencies[$byte]++
    }
    
    foreach ($frequency in $frequencies.Values) {
        $probability = $frequency / $length
        $entropy -= $probability * [Math]::Log($probability, 2)
    }
    
    $normalizedEntropy = $entropy / 8.0
    $classification = if ($normalizedEntropy -gt 0.85) { "HIGH - Possibly encrypted or compressed" }
    elseif ($normalizedEntropy -gt 0.70) { "MEDIUM - Further analysis recommended" }
    elseif ($normalizedEntropy -gt 0.40) { "NORMAL - Standard file structure" }
    else { "LOW - Likely plain text" }
    
    $riskScore = if ($normalizedEntropy -gt 0.85) { 85 } else { [math]::Round($normalizedEntropy * 100) }
    
    return @{
        EntropyValue = [math]::Round($normalizedEntropy, 4)
        Classification = $classification
        RiskScore = $riskScore
    }
}

function Invoke-RustBinaryScanner {
    param([string]$FilePath)
    
    $rustBinaryPath = Join-Path $PSScriptRoot "src\核心扫描引擎\target\release\binary_scanner.exe"
    
    if (-not (Test-Path $rustBinaryPath)) {
        Write-Warning "Rust scanner not compiled. Run: cargo build --release in src/核心扫描引擎/"
        return @{
            Status = "ScannerNotAvailable"
            Message = "Binary scanner not found - falling back to PowerShell mode"
            Entropy = 0
            YaraMatches = 0
            SuspiciousStreams = 0
        }
    }
    
    $result = & $rustBinaryPath --file $FilePath --mode parallel --hashes sha256,sha512,md5 --yara-scan --entropy
    return $result | ConvertFrom-Json
}

function Invoke-PythonPDFAnalyzer {
    param([string]$FilePath)
    
    $pythonScript = Join-Path $PSScriptRoot "src\文档分析器\pdf_analyzer.py"
    
    if (-not (Test-Path $pythonScript)) {
        Write-Warning "Python analyzer not found: $pythonScript"
        return $null
    }
    
    $result = & python $pythonScript --file $FilePath --deep-analysis --extract-javascript --detect-streams 2>&1
    $resultString = $result | Out-String
    
    try {
        return $resultString | ConvertFrom-Json
    }
    catch {
        Write-Warning "Failed to parse Python output: $_"
        return $null
    }
}

function Invoke-TypeScriptScriptAnalyzer {
    param([string]$FilePath)
    
    $tsScript = Join-Path $PSScriptRoot "src\脚本分析引擎\dist\script_analyzer.js"
    
    if (-not (Test-Path $tsScript)) {
        Write-Warning "Script analyzer not found: $tsScript"
        return $null
    }
    
    $result = & node $tsScript --file $FilePath --static-analysis --detect-obfuscation 2>&1
    $resultString = $result | Out-String
    
    try {
        return $resultString | ConvertFrom-Json
    }
    catch {
        Write-Warning "Failed to parse Node.js output: $_"
        return $null
    }
}

function Start-DocCoreScan {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [switch]$DeepScan,
        [switch]$StripMetadata,
        [switch]$ExtractPayloads,
        [ValidateSet("JSON", "XML", "Terminal")]
        [string]$OutputFormat = "JSON"
    )
    
    $session = [DocCoreSession]::new()
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    Write-Host "HeWen DocCore v3.0 - Session: $($session.SessionId)" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor DarkCyan
    
    if (-not (Test-Path $FilePath)) {
        Write-Error "File not found: $FilePath"
        return
    }
    
    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $fileInfo = Get-Item $FilePath
    
    Write-Host "[1/6] Computing cryptographic hashes (SHA-256, SHA-512, MD5)" -ForegroundColor Yellow
    $sha256 = [SHA256]::Create().ComputeHash($fileBytes)
    $sha512 = [SHA512]::Create().ComputeHash($fileBytes)
    $md5 = [MD5]::Create().ComputeHash($fileBytes)
    
    $fingerprint = [DocumentFingerprint]@{
        SHA256 = [BitConverter]::ToString($sha256) -replace '-',''
        SHA512 = [BitConverter]::ToString($sha512) -replace '-',''
        MD5 = [BitConverter]::ToString($md5) -replace '-',''
        EntropyScore = "Calculating..."
        FileSize = $fileInfo.Length
        MagicBytes = Get-MagicBytesIdentification -FileHeader $fileBytes[0..7]
        StructuralAnomalies = @{}
    }
    
    Write-Host "[2/6] Calculating Shannon Entropy" -ForegroundColor Yellow
    $entropyResult = Invoke-ShannonEntropyCalculation -Data $fileBytes
    $fingerprint.EntropyScore = "$($entropyResult.EntropyValue) - $($entropyResult.Classification)"
    
    Write-Host "[3/6] Launching Rust parallel scanner" -ForegroundColor Yellow
    $scanResult = Invoke-RustBinaryScanner -FilePath $FilePath
    
    Write-Host "[4/6] Python PDF/Office deep structure analysis" -ForegroundColor Yellow
    $documentAnalysis = $null
    if ($fingerprint.MagicBytes -match "PDF|OLE2|Office|Compound|Open XML") {
        $documentAnalysis = Invoke-PythonPDFAnalyzer -FilePath $FilePath
    }
    
    Write-Host "[5/6] TypeScript static script analysis" -ForegroundColor Yellow
    $scriptAnalysis = Invoke-TypeScriptScriptAnalyzer -FilePath $FilePath
    
    Write-Host "[6/6] C++ memory buffer operations" -ForegroundColor Yellow
    if ($StripMetadata) {
        $cppHandler = Join-Path $PSScriptRoot "src\内存处理核心\build\memory_handler.exe"
        if (Test-Path $cppHandler) {
            & $cppHandler --file $FilePath --strip-metadata --output "$FilePath.cleaned"
        }
        else {
            Write-Warning "C++ handler not compiled"
        }
    }
    
    $stopwatch.Stop()
    
    $threatLevel = Calculate-ThreatLevel -ScanResult $scanResult -DocAnalysis $documentAnalysis -ScriptAnalysis $scriptAnalysis -EntropyResult $entropyResult
    
    $results = @{
        SessionId = $session.SessionId
        FileName = $fileInfo.Name
        FilePath = $FilePath
        AnalysisTimestamp = [datetime]::Now.ToString("yyyy-MM-dd HH:mm:ss.fff")
        AnalysisDuration = "$([math]::Round($stopwatch.Elapsed.TotalSeconds, 4)) seconds"
        Fingerprint = $fingerprint
        EntropyAnalysis = $entropyResult
        BinaryScan = $scanResult
        DocumentAnalysis = if ($documentAnalysis) { $documentAnalysis } else { "N/A - Not a supported document format or analyzer unavailable" }
        ScriptAnalysis = if ($scriptAnalysis) { $scriptAnalysis } else { "N/A - Script analysis unavailable" }
        ThreatLevel = $threatLevel
    }
    
    switch ($OutputFormat) {
        "JSON" {
            $results | ConvertTo-Json -Depth 10
        }
        "Terminal" {
            Write-Host "`n=== SCAN RESULTS ===" -ForegroundColor Green
            Write-Host "Threat Level: $($results.ThreatLevel)" -ForegroundColor $(if($results.ThreatLevel -match "CRITICAL|HIGH"){"Red"}elseif($results.ThreatLevel -match "MEDIUM"){"Yellow"}else{"Green"})
            Write-Host "Entropy: $($entropyResult.EntropyValue)" -ForegroundColor White
            Write-Host "Duration: $($results.AnalysisDuration)" -ForegroundColor White
        }
    }
    
    return $results
}

function Calculate-ThreatLevel {
    param(
        $ScanResult,
        $DocAnalysis,
        $ScriptAnalysis,
        $EntropyResult
    )
    
    $threatScore = 0
    
    if ($EntropyResult.EntropyValue -gt 0.85) { $threatScore += 30 }
    elseif ($EntropyResult.EntropyValue -gt 0.70) { $threatScore += 15 }
    
    if ($ScanResult.YaraMatches -and $ScanResult.YaraMatches.Count -gt 0) { $threatScore += 40 }
    
    if ($DocAnalysis -and $DocAnalysis -ne "N/A - Not a supported document format or analyzer unavailable") {
        if ($DocAnalysis.risk_score -gt 70) { $threatScore += 30 }
        elseif ($DocAnalysis.risk_score -gt 40) { $threatScore += 15 }
        if ($DocAnalysis.javascript_injections -and $DocAnalysis.javascript_injections.Count -gt 0) { $threatScore += 25 }
    }
    
    if ($ScriptAnalysis -and $ScriptAnalysis -ne "N/A - Script analysis unavailable") {
        if ($ScriptAnalysis.riskAssessment) {
            if ($ScriptAnalysis.riskAssessment.score -gt 70) { $threatScore += 25 }
            elseif ($ScriptAnalysis.riskAssessment.score -gt 40) { $threatScore += 10 }
        }
    }
    
    if ($threatScore -ge 70) { return "CRITICAL - Immediate isolation required" }
    elseif ($threatScore -ge 40) { return "HIGH - Investigation needed" }
    elseif ($threatScore -ge 20) { return "MEDIUM - Monitor closely" }
    else { return "LOW - No immediate threat" }
}

function Invoke-HeWenAnalysis {
    Start-DocCoreScan @args
}

Set-Alias -Name hewenscan -Value Invoke-HeWenAnalysis
Set-Alias -Name doccore -Value Start-DocCoreScan

Export-ModuleMember -Function Start-DocCoreScan, Invoke-HeWenAnalysis, Get-DocumentFingerprint, Invoke-DeepMemoryAnalysis, Invoke-ShannonEntropyCalculation
Export-ModuleMember -Alias hewenscan, doccore
