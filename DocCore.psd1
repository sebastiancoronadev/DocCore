@{
    RootModule = 'DocCore.psm1'
    ModuleVersion = '3.0.0'
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author = 'Senior Security Architect'
    CompanyName = 'DocCore Security Suite'
    Copyright = '(c) 2024 DocCore. 版权所有'
    Description = '核心文档安全分析引擎 - 无界面，纯命令行操作'
    PowerShellVersion = '5.1'
    RequiredModules = @()
    FunctionsToExport = @(
        'Invoke-HeWenAnalysis',
        'Start-DocCoreScan',
        'Invoke-DeepMemoryAnalysis',
        'Get-DocumentFingerprint',
        'Invoke-MaliciousPayloadExtraction',
        'Clear-DocumentMetadata',
        'Invoke-ParallelSignatureScan',
        'Get-EntropyCalculation'
    )
    CmdletsToExport = @()
    VariablesToExport = '*'
    AliasesToExport = @('hewenscan', 'doccore')
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Malware', 'PDF', 'Office', 'Forensics')
            LicenseUri = 'https://github.com/yourusername/DocCore/LICENSE'
            ProjectUri = 'https://github.com/yourusername/DocCore'
        }
    }
}
