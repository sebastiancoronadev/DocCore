规则 PDF_Javascript_注入 {
    元数据:
        描述 = "检测包含嵌入式JavaScript对象的PDF文件"
        严重性 = "高危"
        作者 = "核文安全团队"
        日期 = "2026-08-02"
    字符串:
        $js1 = "/JavaScript" ascii wide
        $js2 = "/JS" ascii wide
        $eval = "eval(" ascii wide
        $launch = "/Launch" ascii wide
        $openaction = "/OpenAction" ascii wide
    条件:
        uint32(0) == 0x46445025 and any of them
}

规则 PDF_嵌入式可执行文件 {
    元数据:
        描述 = "检测包含嵌入式可执行文件的PDF文件"
        严重性 = "严重"
        作者 = "核文安全团队"
        日期 = "2026-08-02"
    字符串:
        $mz = "MZ" ascii
        $pe = "PE" ascii
        $elf = { 7F 45 4C 46 }
    条件:
        uint32(0) == 0x46445025 and any of them
}

规则 办公文档_自动打开宏 {
    元数据:
        描述 = "检测带有AutoOpen宏的Office文档"
        严重性 = "高危"
        作者 = "核文安全团队"
        日期 = "2026-08-02"
    字符串:
        $autoopen = "AutoOpen" ascii wide nocase
        $documentopen = "Document_Open" ascii wide nocase
        $workbookopen = "Workbook_Open" ascii wide nocase
        $shell = "WScript.Shell" ascii wide nocase
        $createobject = "CreateObject" ascii wide nocase
    条件:
        any of them
}

规则 办公文档_PowerShell执行 {
    元数据:
        描述 = "检测执行PowerShell命令的Office宏"
        严重性 = "严重"
        作者 = "核文安全团队"
        日期 = "2026-08-02"
    字符串:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "-enc " ascii wide
        $ps3 = "ExecutionPolicy Bypass" ascii wide nocase
        $ps4 = "Invoke-Expression" ascii wide nocase
        $ps5 = "IEX" ascii wide
    条件:
        2 of them
}

规则 PE_嵌入式可执行文件 {
    元数据:
        描述 = "检测任何文件中嵌入的PE可执行文件"
        严重性 = "高危"
        作者 = "核文安全团队"
        日期 = "2026-08-02"
    字符串:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    条件:
        $mz and $pe
}

规则 空指令滑板_Shellcode {
    元数据:
        描述 = "检测shellcode中常用的NOP滑板"
        严重性 = "中危"
        作者 = "核文安全团队"
        日期 = "2026-08-02"
    字符串:
        $nop1 = { 90 90 90 90 90 90 90 90 }
        $nop2 = { 0F 1F 00 0F 1F 00 0F 1F 00 }
    条件:
        any of them
}

规则 Base64_编码载荷 {
    元数据:
        描述 = "检测大型Base64编码字符串"
        严重性 = "中危"
        作者 = "核文安全团队"
        日期 = "2026-08-02"
    字符串:
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
    条件:
        #b64 > 5
}

规则 中文来源文档 {
    元数据:
        描述 = "标记包含中文字符编码的文档"
        严重性 = "低危"
        作者 = "核文安全团队"
        日期 = "2026-08-02"
    条件:
        for any i in (0..filesize): {
            uint8(i) >= 0xE4 and uint8(i) <= 0xE9
        }
}
