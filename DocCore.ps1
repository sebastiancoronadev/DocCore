param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,
    
    [switch]$DeepScan,
    [switch]$StripMetadata,
    [string]$OutputFormat = "JSON"
)

$modulePath = Join-Path $PSScriptRoot "DocCore.psd1"

if (-not (Get-Module -Name DocCore)) {
    Import-Module $modulePath -Force
}

$result = Start-DocCoreScan -FilePath $FilePath -DeepScan:$DeepScan -StripMetadata:$StripMetadata -OutputFormat $OutputFormat

if ($OutputFormat -eq "JSON") {
    $outputFile = "$FilePath.DocCore_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
    Write-Host "报告已保存至: $outputFile" -ForegroundColor Green
}
