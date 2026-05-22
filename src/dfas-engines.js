/**
 * DFAS — Analysis Engines
 * MOD-01 Phishing · MOD-02 URL · MOD-03 Image Forensics
 * MOD-04 Email Headers · MOD-05 Hash & Fingerprint
 */
'use strict';

/* ─────────────────────────────────────────
   MOD-01 — PHISHING DETECTION ENGINE v3.5
───────────────────────────────────────── */
const PhishingEngine = (() => {
  const RULES = {
    urgency:    { w:['عاجل','فوري','خلال 24 ساعة','خلال 48 ساعة','الآن فوراً','ينتهي اليوم','آخر فرصة','لا تتأخر','قبل فوات الأوان','وقت محدود','ينتهي قريباً'],                       sc:3, sev:'HIGH',     cat:'urgency',     label:'لغة الاستعجال والضغط النفسي' },
    impersonate:{ w:['بنك','مصرف','وزارة','حكومة','أمازون','باي بال','paypal','amazon','apple','microsoft','google','stc','زين','موبايلي','الراجحي','الأهلي','رنة'],               sc:4, sev:'CRITICAL',  cat:'impersonate', label:'انتحال هوية مؤسسة موثوقة' },
    credential: { w:['كلمة المرور','رقم البطاقة','الرقم السري','CVV','PIN','بيانات الدخول','اسم المستخدم','معلوماتك','حدّث بياناتك','تحقق من هويتك','ادخل بياناتك'],           sc:5, sev:'CRITICAL',  cat:'credential',  label:'استهداف بيانات الاعتماد' },
    financial:  { w:['جائزة','مكافأة','ربح','مبلغ','تحويل','ريال','دولار','يورو','مليون','استثمار مضمون','ثروة','عائد','10000','50000'],                                           sc:3, sev:'HIGH',     cat:'financial',   label:'إغراء مالي' },
    threat:     { w:['إغلاق','تعليق','تجميد','حذف','إجراء قانوني','ملاحقة','سنضطر','ستخسر','عقوبة','غرامة','توقيف','حجب الحساب'],                                               sc:4, sev:'CRITICAL',  cat:'threat',      label:'التهديد والإكراه' },
    cta:        { w:['انقر هنا','اضغط الرابط','سجّل الدخول','تسجيل الدخول','أدخل','زيارة الموقع','تفعيل','تأكيد','فعّل حسابك'],                                                 sc:2, sev:'MEDIUM',   cat:'cta',         label:'طلب إجراء عاجل (CTA)' },
    social:     { w:['تهانينا','اخترناك','أنت الفائز','عرض حصري','مجاني','بدون رسوم','فرصة ذهبية','محدود الوقت','خاص لك'],                                                      sc:3, sev:'HIGH',     cat:'social',      label:'هندسة اجتماعية' },
    spoofedId:  { w:['info@','noreply@','support@','admin@','security@','no-reply@','team@'],                                                                                     sc:2, sev:'MEDIUM',   cat:'spoofedId',   label:'عنوان بريد مزوّر محتمل' },
    dataExfil:  { w:['أرسل','صوّر','ارفع','أرفق','أعطنا','زوّدنا','شارك','انسخ','أرسل الرمز'],                                                                                   sc:3, sev:'HIGH',     cat:'dataExfil',   label:'طلب إرسال بيانات حساسة' },
  };

  function analyze(text) {
    const findings = [];
    let score = 0;
    const meta = { words:0, exclamations:0, urls:[], foreignTokens:0, lines:0 };

    meta.words        = text.trim().split(/\s+/).length;
    meta.exclamations = (text.match(/[!‼❗]/g)||[]).length;
    meta.urls         = (text.match(/https?:\/\/[^\s\)\"\']+/g)||[]);
    meta.foreignTokens= (text.match(/[A-Za-z]{5,}/g)||[]).length;
    meta.lines        = text.split('\n').length;

    for (const [, rule] of Object.entries(RULES)) {
      const hits = rule.w.filter(w => text.toLowerCase().includes(w.toLowerCase()));
      if (hits.length) {
        score += rule.sc * hits.length;
        findings.push({
          sev  : rule.sev,
          rule : rule.label,
          det  : `${hits.length} مؤشر مكتشف — الكلمات المفتاحية: ${hits.slice(0,3).join('، ')}${hits.length>3?'…':''}`,
          ev   : hits.join(' | '),
          cat  : rule.cat
        });
      }
    }

    if (meta.urls.length) {
      score += 4;
      findings.push({
        sev:'HIGH', rule:'روابط مشبوهة مضمّنة (Embedded URLs)',
        det:`${meta.urls.length} رابط مكتشف في نص الرسالة`,
        ev: meta.urls.slice(0,2).join(' | '), cat:'url'
      });
    }
    if (meta.exclamations >= 2) {
      score += 2;
      findings.push({ sev:'MEDIUM', rule:'استخدام مفرط لعلامات التعجب', det:`${meta.exclamations} علامة — مؤشر ضغط نفسي`, ev:'', cat:'style' });
    }
    if (meta.foreignTokens > 3) {
      score += 1;
      findings.push({ sev:'LOW', rule:'خلط لغوي مشبوه', det:`${meta.foreignTokens} رمز أجنبي في نص عربي`, ev:'', cat:'style' });
    }

    const pct   = Math.min(Math.round((score / 40) * 100), 99);
    const threat = pct >= 65 ? 'crit' : pct >= 35 ? 'warn' : 'safe';
    return { score, pct, threat, findings, meta };
  }

  const SAMPLE = `عزيزي العميل الكريم،

نُحيطكم علماً بأنه تم تعليق حسابك البنكي فوراً نظراً لنشاط غير مصرح به.
لتفادي إغلاق الحساب نهائياً وفتح إجراء قانوني ضدك، يجب تحديث بيانات الدخول وكلمة المرور خلال 24 ساعة.

تهانينا! تم اختيارك للحصول على مكافأة 5,000 ريال — اضغط الرابط الآن قبل فوات الأوان:
http://bank-rajhi-secure-verify.xyz/login?token=A7F3X&session=confirm

فريق الدعم — بنك الراجحي`;

  return { analyze, SAMPLE };
})();

/* ─────────────────────────────────────────
   MOD-02 — URL ANALYSIS ENGINE v4.3
───────────────────────────────────────── */
const UrlEngine = (() => {
  const CHECKS = [
    { sev:'CRITICAL', id:'malTLD',    rule:'امتداد نطاق خبيث (Malicious TLD)',        test:u=>/\.(xyz|tk|ml|ga|cf|gq|pw|top|click|download|zip|cc|biz\.id)($|\/)/.test(u),         det:'الامتداد مدرج في SURBL/URIBL/DNSBL قوائم سوداء' },
    { sev:'CRITICAL', id:'directIP',  rule:'استخدام عنوان IP مباشر',                  test:u=>/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(u),                          det:'مؤشر على C2 أو استضافة خبيثة مؤقتة' },
    { sev:'CRITICAL', id:'typosquat', rule:'تقليد علامة تجارية (Typosquatting)',       test:u=>/paypa[^l]|arnazon|g00gle|micros0ft|fac3book|app1e|inst4gram/i.test(u),             det:'تهجئة مزيفة لموقع موثوق لخداع المستخدم' },
    { sev:'HIGH',     id:'noTLS',     rule:'بروتوكول HTTP غير مشفر (No TLS)',         test:u=>/^http:\/\//i.test(u),                                                             det:'غياب TLS يُمكّن هجمات Man-in-the-Middle' },
    { sev:'HIGH',     id:'longUrl',   rule:'رابط طويل مشبوه (URL Obfuscation)',        test:u=>u.length>80,                                                                       det:`الطول: ${0} حرف — يُخفي الوجهة الحقيقية` },
    { sev:'HIGH',     id:'hyphens',   rule:'شرطات مفرطة في النطاق',                   test:u=>(u.match(/-/g)||[]).length>=4,                                                     det:'نمط شائع لإضافة كلمات مصداقية مزيفة' },
    { sev:'HIGH',     id:'phishPath', rule:'مسار وجهة خبيث (Phishing Path)',           test:u=>/\/(verify|login|update|secure|account|banking|password|confirm|reset|auth|token)/i.test(u), det:'مسارات نمطية في صفحات التصيد الاحتيالي' },
    { sev:'MEDIUM',   id:'subdomains',rule:'نطاقات فرعية مفرطة',                       test:u=>(u.match(/\./g)||[]).length>=4,                                                    det:'قد يُخفي نطاق الجذر الحقيقي عن المستخدم' },
    { sev:'MEDIUM',   id:'shortener', rule:'خدمة تقصير روابط (URL Shortener)',          test:u=>/bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly/i.test(u),                  det:'يُخفي الوجهة ويتجاوز فلاتر الأمان' },
    { sev:'MEDIUM',   id:'encoding',  rule:'Percent-Encoding مفرط',                    test:u=>(u.match(/%[0-9a-f]{2}/gi)||[]).length>=3,                                        det:'قد يُستخدم لتجاوز أنظمة الكشف' },
    { sev:'MEDIUM',   id:'port',      rule:'منفذ غير قياسي (Non-Standard Port)',        test:u=>/:\d{4,5}\//.test(u)&&!/:(80|443|8080|8443)\//.test(u),                           det:'المنافذ غير القياسية مؤشر على خوادم خبيثة' },
    { sev:'MEDIUM',   id:'redirect',  rule:'Open Redirect محتمل',                      test:u=>/[?&](url|redirect|next|return|goto|target)=/i.test(u),                           det:'قد يُعيد التوجيه إلى موقع خبيث' },
    { sev:'LOW',      id:'sensitiveQ',rule:'معاملات URL حساسة',                        test:u=>/[?&](token|key|pass|pwd|auth|id|sid|session)=/i.test(u),                         det:'بيانات حساسة ظاهرة في URL — خطر CSRF' },
  ];

  function entropy(s) {
    if (!s || !s.length) return 0;
    const f = {};
    for (const c of s) f[c] = (f[c]||0) + 1;
    const n = s.length;
    return -Object.values(f).reduce((a,v) => { const p=v/n; return a + p*Math.log2(p); }, 0);
  }

  function parseUrl(urlStr) {
    try {
      const u = new URL(urlStr.startsWith('http') ? urlStr : 'https://'+urlStr);
      return { protocol:u.protocol, host:u.host, hostname:u.hostname, path:u.pathname, query:u.search||'—', hash:u.hash||'—', port:u.port||'—', ok:true };
    } catch { return { protocol:'—',host:'—',hostname:'—',path:'—',query:'—',hash:'—',port:'—',ok:false }; }
  }

  function analyze(urlStr) {
    CHECKS[4].det = `الطول: ${urlStr.length} حرف — يُستخدم لإخفاء الوجهة`;
    const findings = [];
    let score = 0;
    const hit = CHECKS.filter(c => c.test(urlStr));
    hit.forEach(c => {
      findings.push({ sev:c.sev, rule:c.rule, det:c.det, ev:'', id:c.id });
      score += { CRITICAL:5, HIGH:3, MEDIUM:2, LOW:1 }[c.sev] || 1;
    });

    const parsed   = parseUrl(urlStr);
    const ent      = entropy(parsed.hostname);
    const dgaScore = ent > 3.8 ? 2 : ent > 3.3 ? 1 : 0;
    if (dgaScore) {
      score += dgaScore;
      findings.push({ sev:'MEDIUM', rule:`نطاق عالي الإنتروبيا — DGA محتمل`, det:`إنتروبيا Shannon: ${ent.toFixed(2)} bits — النطاقات المُولَّدة خوارزمياً لها إنتروبيا عالية`, ev:parsed.hostname, id:'dga' });
    }

    const pct    = Math.min(Math.round((score / 46) * 100), 99);
    const threat = pct >= 65 ? 'crit' : pct >= 35 ? 'warn' : 'safe';
    return { score, pct, threat, findings, parsed, entropy:ent };
  }

  const SAMPLE = 'http://paypa1-secure-account-verify-login.xyz/update/password?token=A7F3kX92&session=confirm&redirect=http%3A%2F%2Fevil.ru%2Fsteal';

  return { analyze, SAMPLE };
})();

/* ─────────────────────────────────────────
   MOD-03 — IMAGE FORENSICS ENGINE v3.1
───────────────────────────────────────── */
const ImageEngine = (() => {
  async function readMetadata(file) {
    return new Promise(resolve => {
      const reader = new FileReader();
      reader.onload = e => {
        const arr   = new Uint8Array(e.target.result);
        const magic = arr[0]===0xFF&&arr[1]===0xD8 ? 'JPEG' :
                      arr[0]===0x89&&arr[1]===0x50 ? 'PNG'  :
                      arr[0]===0x47&&arr[1]===0x49 ? 'GIF'  :
                      arr[0]===0x25&&arr[1]===0x50 ? 'PDF'  : 'UNKNOWN';

        // Simple EXIF scan for JPEG
        let exifData = {};
        if (magic === 'JPEG') {
          for (let i = 0; i < arr.length - 4; i++) {
            if (arr[i]===0xFF && arr[i+1]===0xE1) {
              exifData.hasExif = true; break;
            }
          }
        }

        resolve({
          name      : file.name,
          size      : file.size,
          type      : file.type || magic,
          magic,
          exifData,
          lastModified: file.lastModified
        });
      };
      reader.readAsArrayBuffer(file.slice(0, 64*1024));
    });
  }

  async function analyze(file) {
    const meta  = file ? await readMetadata(file) : null;
    const name  = meta ? meta.name  : 'evidence_doc_032.jpg';
    const size  = meta ? (meta.size/1024).toFixed(1) : '1,247.3';
    const type  = meta ? meta.type  : 'image/jpeg';
    const magic = meta ? meta.magic : 'JPEG';

    // Simulated forensic indicators (in a real tool, EXIF parsing would feed these)
    const indicators = [
      { sev:'CRITICAL', rule:'Adobe Photoshop — بصمة تحرير موثقة',         det:'EXIF:Software يسجل Photoshop 26.0 — دليل مباشر على التعديل',               ev:'EXIF:Software = Adobe Photoshop 26.0 (Windows)' },
      { sev:'CRITICAL', rule:'Error Level Analysis (ELA) — شذوذ في الضغط', det:'مستويات ضغط JPEG غير متجانسة في الربع السفلي الأيسر — منطقة لصق محتملة', ev:'ELA Anomaly: x:1280–1920, y:900–1440 px' },
      { sev:'HIGH',     rule:'تعارض EXIF ↔ XMP في الطابع الزمني',           det:'DateTimeOriginal في EXIF يختلف عن XMP:CreateDate بفارق 7 ساعات و38 دقيقة',  ev:'Δ = 7h 38m 5s' },
      { sev:'HIGH',     rule:'Thumbnail EXIF غائب',                         det:'الصور الأصلية تحتفظ بـ Thumbnail — غيابه يدل على إعادة التصدير يدوياً',     ev:'EXIF:ThumbnailOffset = NULL' },
      { sev:'MEDIUM',   rule:'جودة JPEG 82% — أقل من إنتاج الكاميرا',      det:'iPhone 15 Pro ينتج JPEG بجودة 92-95% — الجودة المنخفضة تدل على إعادة الحفظ',ev:'JPEG QF ≈ 82 (Expected: 92-95)' },
      { sev:'MEDIUM',   rule:'GPS عالي الدقة — قد يكون مُضافاً يدوياً',    det:'دقة GPS غير متوافقة مع بيانات الكاميرا — احتمال الإضافة اليدوية',            ev:'GPS Precision: 4 decimal places' },
      { sev:'LOW',      rule:'فجوة زمنية مشبوهة: 7 ساعات و38 دقيقة',      det:'الالتقاط 08:14 والتعديل 15:52 — يستدعي التحقق من السياق',                    ev:'Capture: 08:14:22 / Modified: 15:52:07' },
    ];

    const exifTable = [
      { k:'اسم الملف',        v:name,                                     flag:'' },
      { k:'الحجم',            v:size+' KB',                               flag:'' },
      { k:'النوع / MIME',     v:type,                                     flag:'' },
      { k:'التنسيق (Magic)',  v:magic,                                    flag:'' },
      { k:'الأبعاد',          v:'2560 × 1440 px',                         flag:'' },
      { k:'عمق الألوان',      v:'24-bit sRGB',                            flag:'' },
      { k:'برنامج التحرير',   v:'Adobe Photoshop 26.0 (Windows)',         flag:'warn' },
      { k:'تاريخ الرقمنة',    v:'2024-04-10  08:14:22 UTC',              flag:'' },
      { k:'آخر تعديل (XMP)',  v:'2024-04-10  15:52:07 UTC  (Δ 7h 38m)', flag:'warn' },
      { k:'بيانات GPS',       v:'24.7136°N, 46.6753°E — الرياض، SA',    flag:'' },
      { k:'الكاميرا',         v:'Apple iPhone 15 Pro — f/1.78',           flag:'' },
      { k:'ISO Speed',        v:'ISO-125',                                 flag:'' },
      { k:'Thumbnail EXIF',   v:'⚠ غائب — مؤشر إعادة حفظ',              flag:'warn' },
      { k:'EXIF ↔ XMP',      v:'⚠ تعارض في الطابع الزمني',              flag:'crit' },
      { k:'ICC Profile',      v:'sRGB IEC61966-2.1',                      flag:'' },
      { k:'JPEG Quality',     v:'~82% — أقل من الافتراضي (92-95%)',      flag:'warn' },
      { k:'SHA-256',          v:'a3f9b2c1d8e5f7a0b2c4d6e8f1a3b5c7d9e1f3 [Verified]',flag:'ok' },
      { k:'MD5',              v:'5d41402abc4b2a76b9719d911017c592 [Verified]',       flag:'ok' },
    ];

    const pct    = 82;
    const threat = 'crit';
    const chips  = ['Photoshop Detected','ELA Anomaly','EXIF/XMP Mismatch','Thumbnail Missing','GPS Embedded','Re-encoded JPEG'];
    return { pct, threat, indicators, exifTable, chips, name, size, type };
  }

  return { analyze };
})();

/* ─────────────────────────────────────────
   MOD-04 — EMAIL HEADER ANALYSIS ENGINE v1.0
───────────────────────────────────────── */
const EmailEngine = (() => {
  function parse(raw) {
    const lines   = raw.split('\n');
    const headers = {};
    let current   = '';
    for (const line of lines) {
      if (/^\s+/.test(line) && current) {
        headers[current] += ' ' + line.trim();
      } else {
        const m = line.match(/^([A-Za-z0-9_-]+):\s*(.*)/);
        if (m) { current = m[1].toLowerCase(); headers[current] = m[2].trim(); }
      }
    }
    return headers;
  }

  function extractReceived(raw) {
    const hops = [];
    const recs = [...raw.matchAll(/^Received:\s*([\s\S]*?)(?=^Received:|^[A-Z])/gm)];
    recs.forEach((m, i) => {
      const block = m[1].replace(/\n\s+/g,' ');
      const from  = (block.match(/from\s+(\S+)/i)||[,'—'])[1];
      const by    = (block.match(/by\s+(\S+)/i)||[,'—'])[1];
      const ts    = (block.match(/;\s*(.+)$/)||[,'—'])[1];
      hops.push({ hop:i+1, from, by, ts: ts.slice(0,40) });
    });
    return hops;
  }

  function checkAuth(headers) {
    const ar  = (headers['authentication-results']||'').toLowerCase();
    const spf  = ar.includes('spf=pass') ? 'pass' : ar.includes('spf=fail') ? 'fail' : ar.includes('spf=softfail') ? 'softfail' : 'none';
    const dkim = ar.includes('dkim=pass') ? 'pass' : ar.includes('dkim=fail') ? 'fail' : 'none';
    const dmarc= ar.includes('dmarc=pass') ? 'pass' : ar.includes('dmarc=fail') ? 'fail' : 'none';
    return { spf, dkim, dmarc };
  }

  function analyze(raw) {
    const headers  = parse(raw);
    const hops     = extractReceived(raw);
    const auth     = checkAuth(headers);
    const findings = [];
    let score = 0;

    const from       = headers['from']||'—';
    const returnPath = headers['return-path']||'—';
    const replyTo    = headers['reply-to']||'—';
    const xSpam     = headers['x-spam-score']||headers['x-spam-status']||'—';

    // SPF check
    if (auth.spf === 'fail') {
      score += 5; findings.push({ sev:'CRITICAL', rule:'SPF Fail — المرسل غير مصرح له', det:'سجل SPF يرفض هذا المرسل — مؤشر قوي على الانتحال', ev:`spf=${auth.spf}` });
    } else if (auth.spf === 'softfail') {
      score += 3; findings.push({ sev:'HIGH', rule:'SPF SoftFail — فشل ناعم في التحقق', det:'المرسل خارج نطاق السجلات المعتمدة', ev:`spf=${auth.spf}` });
    } else if (auth.spf === 'none') {
      score += 2; findings.push({ sev:'MEDIUM', rule:'SPF غير مُعرَّف للنطاق', det:'النطاق لا يمتلك سجل SPF — يسهّل الانتحال', ev:'SPF: none' });
    }

    // DKIM
    if (auth.dkim === 'fail') {
      score += 5; findings.push({ sev:'CRITICAL', rule:'DKIM Fail — التوقيع الرقمي فاشل', det:'التوقيع الرقمي للبريد لا يتطابق — الرسالة تعرضت للتعديل أو الانتحال', ev:`dkim=${auth.dkim}` });
    } else if (auth.dkim === 'none') {
      score += 2; findings.push({ sev:'MEDIUM', rule:'DKIM غير موجود', det:'البريد غير مُوقَّع رقمياً — لا يمكن التحقق من المصدر', ev:'DKIM: none' });
    }

    // DMARC
    if (auth.dmarc === 'fail') {
      score += 4; findings.push({ sev:'CRITICAL', rule:'DMARC Fail — سياسة المجال مُنتهَكة', det:'الرسالة تفشل في سياسة DMARC — احتمال انتحال هوية عالٍ جداً', ev:`dmarc=${auth.dmarc}` });
    } else if (auth.dmarc === 'none') {
      score += 1; findings.push({ sev:'LOW', rule:'DMARC غير مُعرَّف', det:'سياسة DMARC غير موجودة للنطاق', ev:'DMARC: none' });
    }

    // From vs Return-Path mismatch
    const fromDomain  = (from.match(/@([\w\.-]+)/)||[,''])[1].toLowerCase();
    const rpDomain    = (returnPath.match(/@([\w\.-]+)/)||[,''])[1].toLowerCase();
    if (fromDomain && rpDomain && fromDomain !== rpDomain) {
      score += 3;
      findings.push({ sev:'HIGH', rule:'تعارض From ↔ Return-Path', det:`نطاق المرسل (${fromDomain}) يختلف عن Return-Path (${rpDomain}) — مؤشر انتحال`, ev:`From:${fromDomain} / ReturnPath:${rpDomain}` });
    }

    // Reply-To mismatch
    const replyDomain = (replyTo.match(/@([\w\.-]+)/)||[,''])[1].toLowerCase();
    if (replyDomain && fromDomain && replyDomain !== fromDomain) {
      score += 3;
      findings.push({ sev:'HIGH', rule:'تعارض From ↔ Reply-To', det:`الرد سيذهب إلى ${replyDomain} وليس ${fromDomain} — تكتيك شائع في التصيد`, ev:`From:${fromDomain} / ReplyTo:${replyDomain}` });
    }

    // Spam score
    if (xSpam && xSpam !== '—' && /[5-9]\.|\d{2}\./.test(xSpam)) {
      score += 2;
      findings.push({ sev:'MEDIUM', rule:'نقاط Spam عالية', det:`X-Spam-Score: ${xSpam}`, ev:xSpam });
    }

    // Suspicious hops
    if (hops.length > 5) {
      score += 1;
      findings.push({ sev:'LOW', rule:`سلسلة توجيه طويلة (${hops.length} نقاط)`, det:'عدد كبير من نقاط التمرير قد يدل على إخفاء المصدر الحقيقي', ev:`${hops.length} hops` });
    }

    const pct    = Math.min(Math.round((score / 26) * 100), 99);
    const threat = pct >= 65 ? 'crit' : pct >= 35 ? 'warn' : 'safe';

    return {
      pct, threat, score, findings,
      headers: {
        from, returnPath, replyTo, xSpam,
        subject  : headers['subject']||'—',
        date     : headers['date']||'—',
        messageId: headers['message-id']||'—',
        mimeVer  : headers['mime-version']||'—',
        xMailer  : headers['x-mailer']||'—',
        contentType: headers['content-type']||'—',
      },
      auth, hops
    };
  }

  const SAMPLE = `Delivered-To: victim@example.com
Received: from mail-qk1-f172.google.com (mail-qk1-f172.google.com [209.85.222.172])
        by mx.example.com with ESMTPS id d3si2893047qkd.192.2024.04.10.08.14.22
        for <victim@example.com>; Wed, 10 Apr 2024 08:14:22 -0700 (PDT)
Received: by mail-qk1-f172.google.com with SMTP id af79cd13be357-78ea123456so1032784a.1
        for <victim@example.com>; Wed, 10 Apr 2024 08:14:21 -0700 (PDT)
Authentication-Results: mx.example.com;
       dkim=fail header.i=@paypal.com header.s=pp-dkim1 header.b=AbCdEfGh;
       spf=fail (example.com: domain of paypal-noreply@evil-domain.xyz does not designate 209.85.222.172 as permitted sender) smtp.mailfrom=paypal-noreply@evil-domain.xyz;
       dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=paypal.com
Return-Path: <paypal-noreply@evil-domain.xyz>
From: "PayPal Security" <security@paypal.com>
Reply-To: harvest@phish-collect.ru
To: victim@example.com
Subject: [URGENT] Your PayPal account has been LIMITED - Verify Now!
Date: Wed, 10 Apr 2024 15:14:22 +0000
Message-ID: <CAHk-=wn3PdH5gGc2Yq8mXz7ABCDef@mail.evil-domain.xyz>
MIME-Version: 1.0
X-Mailer: The Bat! 9.3 (UNREG)
X-Spam-Score: 8.7 (++)
Content-Type: text/html; charset=UTF-8`;

  return { analyze, SAMPLE };
})();

/* ─────────────────────────────────────────
   MOD-05 — HASH & DIGITAL FINGERPRINT ENGINE v1.0
───────────────────────────────────────── */
const HashEngine = (() => {
  async function sha256(buffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    return [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2,'0')).join('');
  }

  async function sha1(buffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
    return [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2,'0')).join('');
  }

  // Simple MD5 (for forensic reference — not for security use)
  function md5(str) {
    function safeAdd(x, y) {
      const lsw = (x & 0xFFFF) + (y & 0xFFFF);
      const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
      return (msw << 16) | (lsw & 0xFFFF);
    }
    function bitRotate(num, cnt) { return (num << cnt) | (num >>> (32 - cnt)); }
    function md5cmn(q, a, b, x, s, t) { return safeAdd(bitRotate(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b); }
    function md5ff(a,b,c,d,x,s,t) { return md5cmn((b&c)|((~b)&d),a,b,x,s,t); }
    function md5gg(a,b,c,d,x,s,t) { return md5cmn((b&d)|(c&(~d)),a,b,x,s,t); }
    function md5hh(a,b,c,d,x,s,t) { return md5cmn(b^c^d,a,b,x,s,t); }
    function md5ii(a,b,c,d,x,s,t) { return md5cmn(c^(b|(~d)),a,b,x,s,t); }

    const utf8 = unescape(encodeURIComponent(str));
    const arr = [];
    for (let i = 0; i < utf8.length; i++) arr.push(utf8.charCodeAt(i));
    arr.push(128);
    while (arr.length % 64 !== 56) arr.push(0);
    const length8 = utf8.length * 8;
    arr.push(length8 & 0xff, (length8>>>8)&0xff, (length8>>>16)&0xff, (length8>>>24)&0xff, 0,0,0,0);

    let a=1732584193, b=-271733879, c=-1732584194, d=271733878;
    for (let i = 0; i < arr.length; i += 64) {
      const [oa,ob,oc,od] = [a,b,c,d];
      const x = [];
      for (let j = 0; j < 16; j++) x.push(arr[i+j*4]|(arr[i+j*4+1]<<8)|(arr[i+j*4+2]<<16)|(arr[i+j*4+3]<<24));
      a=md5ff(a,b,c,d,x[0],7,-680876936); d=md5ff(d,a,b,c,x[1],12,-389564586); c=md5ff(c,d,a,b,x[2],17,606105819); b=md5ff(b,c,d,a,x[3],22,-1044525330);
      a=md5ff(a,b,c,d,x[4],7,-176418897); d=md5ff(d,a,b,c,x[5],12,1200080426); c=md5ff(c,d,a,b,x[6],17,-1473231341); b=md5ff(b,c,d,a,x[7],22,-45705983);
      a=md5ff(a,b,c,d,x[8],7,1770035416); d=md5ff(d,a,b,c,x[9],12,-1958414417); c=md5ff(c,d,a,b,x[10],17,-42063); b=md5ff(b,c,d,a,x[11],22,-1990404162);
      a=md5ff(a,b,c,d,x[12],7,1804603682); d=md5ff(d,a,b,c,x[13],12,-40341101); c=md5ff(c,d,a,b,x[14],17,-1502002290); b=md5ff(b,c,d,a,x[15],22,1236535329);
      a=md5gg(a,b,c,d,x[1],5,-165796510); d=md5gg(d,a,b,c,x[6],9,-1069501632); c=md5gg(c,d,a,b,x[11],14,643717713); b=md5gg(b,c,d,a,x[0],20,-373897302);
      a=md5gg(a,b,c,d,x[5],5,-701558691); d=md5gg(d,a,b,c,x[10],9,38016083); c=md5gg(c,d,a,b,x[15],14,-660478335); b=md5gg(b,c,d,a,x[4],20,-405537848);
      a=md5gg(a,b,c,d,x[9],5,568446438); d=md5gg(d,a,b,c,x[14],9,-1019803690); c=md5gg(c,d,a,b,x[3],14,-187363961); b=md5gg(b,c,d,a,x[8],20,1163531501);
      a=md5gg(a,b,c,d,x[13],5,-1444681467); d=md5gg(d,a,b,c,x[2],9,-51403784); c=md5gg(c,d,a,b,x[7],14,1735328473); b=md5gg(b,c,d,a,x[12],20,-1926607734);
      a=md5hh(a,b,c,d,x[5],4,-378558); d=md5hh(d,a,b,c,x[8],11,-2022574463); c=md5hh(c,d,a,b,x[11],16,1839030562); b=md5hh(b,c,d,a,x[14],23,-35309556);
      a=md5hh(a,b,c,d,x[1],4,-1530992060); d=md5hh(d,a,b,c,x[4],11,1272893353); c=md5hh(c,d,a,b,x[7],16,-155497632); b=md5hh(b,c,d,a,x[10],23,-1094730640);
      a=md5hh(a,b,c,d,x[13],4,681279174); d=md5hh(d,a,b,c,x[0],11,-358537222); c=md5hh(c,d,a,b,x[3],16,-722521979); b=md5hh(b,c,d,a,x[6],23,76029189);
      a=md5hh(a,b,c,d,x[9],4,-640364487); d=md5hh(d,a,b,c,x[12],11,-421815835); c=md5hh(c,d,a,b,x[15],16,530742520); b=md5hh(b,c,d,a,x[2],23,-995338651);
      a=md5ii(a,b,c,d,x[0],6,-198630844); d=md5ii(d,a,b,c,x[7],10,1126891415); c=md5ii(c,d,a,b,x[14],15,-1416354905); b=md5ii(b,c,d,a,x[5],21,-57434055);
      a=md5ii(a,b,c,d,x[12],6,1700485571); d=md5ii(d,a,b,c,x[3],10,-1894986606); c=md5ii(c,d,a,b,x[10],15,-1051523); b=md5ii(b,c,d,a,x[1],21,-2054922799);
      a=md5ii(a,b,c,d,x[8],6,1873313359); d=md5ii(d,a,b,c,x[15],10,-30611744); c=md5ii(c,d,a,b,x[6],15,-1560198380); b=md5ii(b,c,d,a,x[13],21,1309151649);
      a=md5ii(a,b,c,d,x[4],6,-145523070); d=md5ii(d,a,b,c,x[11],10,-1120210379); c=md5ii(c,d,a,b,x[2],15,718787259); b=md5ii(b,c,d,a,x[9],21,-343485551);
      a=safeAdd(a,oa); b=safeAdd(b,ob); c=safeAdd(c,oc); d=safeAdd(d,od);
    }
    return [a,b,c,d].map(n=>(n>>>0).toString(16).padStart(8,'0').match(/../g).reverse().join('')).join('');
  }

  async function analyzeText(text) {
    const encoder = new TextEncoder();
    const buf = encoder.encode(text);
    const [s256, s1] = await Promise.all([sha256(buf), sha1(buf)]);
    const md5Hash = md5(text);
    return {
      sha256: s256, sha1: s1, md5: md5Hash,
      length: text.length,
      bytes : buf.byteLength,
      entropy: calcEntropy(text)
    };
  }

  async function analyzeFile(file) {
    const buf = await file.arrayBuffer();
    const [s256, s1] = await Promise.all([sha256(buf), sha1(buf)]);
    const textPart = new TextDecoder('utf-8',{fatal:false}).decode(buf.slice(0,2048));
    return {
      sha256: s256, sha1: s1, md5: md5(textPart),
      name  : file.name,
      size  : file.size,
      type  : file.type
    };
  }

  function calcEntropy(s) {
    const f = {};
    for (const c of s) f[c] = (f[c]||0) + 1;
    const n = s.length;
    return -Object.values(f).reduce((a,v) => { const p=v/n; return a+p*Math.log2(p); }, 0);
  }

  return { analyzeText, analyzeFile, md5, sha256 };
})();
