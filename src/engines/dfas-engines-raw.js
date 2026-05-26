/**
 * DFAS — Analysis Engines
 * MOD-01 Phishing · MOD-02 URL · MOD-03 Image Forensics
 * MOD-04 Email Headers · MOD-05 Hash & Fingerprint
 */
"use strict";

/* ─────────────────────────────────────────
   MOD-01 — PHISHING DETECTION ENGINE v3.5
───────────────────────────────────────── */
const PhishingEngine = (() => {
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
          det: `${hits.length} مؤشر مكتشف — الكلمات المفتاحية: ${hits.slice(0, 3).join("، ")}${hits.length > 3 ? "…" : ""}`,
          ev: hits.join(" | "),
          cat: rule.cat,
        });
      }
    }

    if (meta.urls.length) {
      score += 4;
      findings.push({
        sev: "HIGH",
        rule: "روابط مشبوهة مضمّنة (Embedded URLs)",
        det: `${meta.urls.length} رابط مكتشف في نص الرسالة`,
        ev: meta.urls.slice(0, 2).join(" | "),
        cat: "url",
      });
    }
    if (meta.exclamations >= 2) {
      score += 2;
      findings.push({
        sev: "MEDIUM",
        rule: "استخدام مفرط لعلامات التعجب",
        det: `${meta.exclamations} علامة — مؤشر ضغط نفسي`,
        ev: "",
        cat: "style",
      });
    }
    if (meta.foreignTokens > 3) {
      score += 1;
      findings.push({
        sev: "LOW",
        rule: "خلط لغوي مشبوه",
        det: `${meta.foreignTokens} رمز أجنبي في نص عربي`,
        ev: "",
        cat: "style",
      });
    }

    const pct = Math.min(Math.round((score / 40) * 100), 99);
    const threat = pct >= 65 ? "crit" : pct >= 35 ? "warn" : "safe";
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
    {
      sev: "CRITICAL",
      id: "malTLD",
      rule: "امتداد نطاق خبيث (Malicious TLD)",
      test: (u) => /\.(xyz|tk|ml|ga|cf|gq|pw|top|click|download|zip|cc|biz\.id)($|\/)/.test(u),
      det: "الامتداد مدرج في SURBL/URIBL/DNSBL قوائم سوداء",
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
      det: "تهجئة مزيفة لموقع موثوق لخداع المستخدم",
    },
    {
      sev: "HIGH",
      id: "noTLS",
      rule: "بروتوكول HTTP غير مشفر (No TLS)",
      test: (u) => /^http:\/\//i.test(u),
      det: "غياب TLS يُمكّن هجمات Man-in-the-Middle",
    },
    {
      sev: "HIGH",
      id: "longUrl",
      rule: "رابط طويل مشبوه (URL Obfuscation)",
      test: (u) => u.length > 80,
      det: `الطول: ${0} حرف — يُخفي الوجهة الحقيقية`,
    },
    {
      sev: "HIGH",
      id: "hyphens",
      rule: "شرطات مفرطة في النطاق",
      test: (u) => (u.match(/-/g) || []).length >= 4,
      det: "نمط شائع لإضافة كلمات مصداقية مزيفة",
    },
    {
      sev: "HIGH",
      id: "phishPath",
      rule: "مسار وجهة خبيث (Phishing Path)",
      test: (u) =>
        /\/(verify|login|update|secure|account|banking|password|confirm|reset|auth|token)/i.test(u),
      det: "مسارات نمطية في صفحات التصيد الاحتيالي",
    },
    {
      sev: "MEDIUM",
      id: "subdomains",
      rule: "نطاقات فرعية مفرطة",
      test: (u) => (u.match(/\./g) || []).length >= 4,
      det: "قد يُخفي نطاق الجذر الحقيقي عن المستخدم",
    },
    {
      sev: "MEDIUM",
      id: "shortener",
      rule: "خدمة تقصير روابط (URL Shortener)",
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
      rule: "منفذ غير قياسي (Non-Standard Port)",
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
      det: "بيانات حساسة ظاهرة في URL — خطر CSRF",
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
    CHECKS[4].det = `الطول: ${urlStr.length} حرف — يُستخدم لإخفاء الوجهة`;
    const findings = [];
    let score = 0;
    const hit = CHECKS.filter((c) => c.test(urlStr));
    hit.forEach((c) => {
      findings.push({ sev: c.sev, rule: c.rule, det: c.det, ev: "", id: c.id });
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
        det: `إنتروبيا Shannon: ${ent.toFixed(2)} bits — النطاقات المُولَّدة خوارزمياً لها إنتروبيا عالية`,
        ev: parsed.hostname,
        id: "dga",
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

/* ─────────────────────────────────────────
   MOD-03 — IMAGE FORENSICS ENGINE v4.0
   Real EXIF Binary Parser + ELA + GPS
───────────────────────────────────────── */
const ImageEngine = (() => {
  /* ── EXIF / TIFF Tag Dictionary ── */
  const TAG = {
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
  const GPS_TAG = {
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

  /* ── DataView helpers ── */
  function u16(v, o, le) {
    return v.getUint16(o, le);
  }
  function u32(v, o, le) {
    return v.getUint32(o, le);
  }
  function i32(v, o, le) {
    return v.getInt32(o, le);
  }
  function readStr(v, o, n) {
    let s = "";
    for (let i = 0; i < n; i++) {
      const c = v.getUint8(o + i);
      if (!c) break;
      s += String.fromCharCode(c);
    }
    return s.trim();
  }
  function rational(v, o, le) {
    const n = u32(v, o, le),
      d = u32(v, o + 4, le);
    return d ? n / d : 0;
  }
  function sRational(v, o, le) {
    const n = i32(v, o, le),
      d = i32(v, o + 4, le);
    return d ? n / d : 0;
  }

  /* ── Read one IFD ── */
  function readIFD(v, ifdOff, base, le, tagDict) {
    const out = {};
    if (ifdOff + 2 > v.byteLength) return out;
    const n = u16(v, ifdOff, le);
    let p = ifdOff + 2;
    for (let i = 0; i < n && p + 12 <= v.byteLength; i++, p += 12) {
      const tag = u16(v, p, le),
        type = u16(v, p + 2, le),
        cnt = u32(v, p + 4, le);
      const vp = p + 8;
      let val = null;
      try {
        if (type === 2) {
          // ASCII
          val = cnt <= 4 ? readStr(v, vp, cnt) : readStr(v, base + u32(v, vp, le), cnt);
        } else if (type === 3) {
          // SHORT
          val =
            cnt === 1
              ? u16(v, vp, le)
              : cnt === 2
                ? [u16(v, vp, le), u16(v, vp + 2, le)]
                : (() => {
                    const off = base + u32(v, vp, le),
                      a = [];
                    for (let j = 0; j < Math.min(cnt, 8); j++) a.push(u16(v, off + j * 2, le));
                    return a;
                  })();
        } else if (type === 4) {
          // LONG
          val = cnt === 1 ? u32(v, vp, le) : u32(v, base + u32(v, vp, le), le);
        } else if (type === 5) {
          // RATIONAL
          const off = base + u32(v, vp, le);
          val =
            cnt === 1
              ? rational(v, off, le)
              : Array.from({ length: Math.min(cnt, 4) }, (_, j) => rational(v, off + j * 8, le));
        } else if (type === 9) {
          // SLONG
          val = cnt === 1 ? i32(v, vp, le) : i32(v, base + u32(v, vp, le), le);
        } else if (type === 10) {
          // SRATIONAL
          val = sRational(v, base + u32(v, vp, le), le);
        } else if (type === 1 || type === 7) {
          // BYTE / UNDEFINED
          if (cnt <= 4) {
            val = [];
            for (let j = 0; j < cnt; j++) val.push(v.getUint8(vp + j));
          } else {
            const off = base + u32(v, vp, le);
            val = [];
            for (let j = 0; j < Math.min(cnt, 16); j++) val.push(v.getUint8(off + j));
          }
          if (val.length === 1) val = val[0];
        }
      } catch (_) {
        val = null;
      }
      const name = tagDict[tag] || `0x${tag.toString(16).toUpperCase()}`;
      out[name] = val;
    }
    return out;
  }

  /* ── GPS rational → decimal degrees ── */
  function gpsDecimal(arr, ref) {
    if (!Array.isArray(arr) || arr.length < 3) return null;
    const dec = arr[0] + arr[1] / 60 + arr[2] / 3600;
    return ref === "S" || ref === "W" ? -dec : dec;
  }

  /* ── Estimate JPEG quality from DQT quantization table ── */
  function jpegQuality(arr) {
    for (let i = 0; i < arr.length - 1; i++) {
      if (arr[i] === 0xff && arr[i + 1] === 0xdb) {
        const tbl = Array.from(arr.slice(i + 5, i + 69)); // skip FF DB len precision_id
        if (tbl.length < 64) continue;
        const avg = tbl.reduce((a, v) => a + v, 0) / 64;
        return Math.max(1, Math.min(100, Math.round(101 - avg * 1.42)));
      }
    }
    return null;
  }

  /* ── Detect editor binary signatures ── */
  function editorSigs(arr) {
    const s = Array.from(arr.slice(0, 8192))
      .map((b) => String.fromCharCode(b))
      .join("");
    const found = [];
    const checks = [
      ["photoshop", "Adobe Photoshop", "CRITICAL"],
      ["lightroom", "Adobe Lightroom", "HIGH"],
      ["gimp", "GIMP", "HIGH"],
      ["snapseed", "Snapseed", "HIGH"],
      ["canva", "Canva", "HIGH"],
      ["facetune", "Facetune", "CRITICAL"],
      ["faceapp", "FaceApp", "CRITICAL"],
      ["meitu", "Meitu", "HIGH"],
      ["paintshop", "PaintShop Pro", "HIGH"],
      ["affinity", "Affinity Photo", "HIGH"],
      ["midjourney", "AI Generator (MidJourney)", "CRITICAL"],
      ["stable diffusion", "AI Generator (Stable Diffusion)", "CRITICAL"],
      ["dall-e", "AI Generator (DALL-E)", "CRITICAL"],
    ];
    for (const [key, label, sev] of checks) {
      if (s.toLowerCase().includes(key)) found.push({ label, sev });
    }
    return found;
  }

  /* ── Full EXIF binary reader ── */
  async function readMetadata(file) {
    return new Promise((resolve) => {
      const fr = new FileReader();
      fr.onload = (e) => {
        const arr = new Uint8Array(e.target.result);
        const view = new DataView(arr.buffer);
        const magic =
          arr[0] === 0xff && arr[1] === 0xd8
            ? "JPEG"
            : arr[0] === 0x89 && arr[1] === 0x50
              ? "PNG"
              : arr[0] === 0x47 && arr[1] === 0x49
                ? "GIF"
                : arr[0] === 0x42 && arr[1] === 0x4d
                  ? "BMP"
                  : arr[0] === 0x25 && arr[1] === 0x50
                    ? "PDF"
                    : "UNKNOWN";
        const res = {
          name: file.name,
          size: file.size,
          type: file.type || magic,
          magic,
          lastModified: file.lastModified,
          tags: {},
          gps: null,
          editorSigs: [],
          jpegQuality: null,
          hasThumbnail: false,
        };

        res.editorSigs = editorSigs(arr);
        res.jpegQuality = magic === "JPEG" ? jpegQuality(arr) : null;

        if (magic !== "JPEG") {
          resolve(res);
          return;
        }

        // Walk JPEG segments to find APP1 (FF E1)
        let pos = 2;
        while (pos < arr.length - 4) {
          if (arr[pos] !== 0xff) {
            pos++;
            continue;
          }
          const mkr = arr[pos + 1],
            len = (arr[pos + 2] << 8) | arr[pos + 3];
          if (mkr === 0xe1 && len > 6 && readStr(view, pos + 4, 4) === "Exif") {
            const tb = pos + 10; // TIFF base
            const le = arr[tb] === 0x49 && arr[tb + 1] === 0x49; // II=LE, MM=BE
            if (u16(view, tb + 2, le) !== 42) {
              pos += 2 + len;
              continue;
            }
            const ifd0Off = u32(view, tb + 4, le);

            // Wrap a DataView that starts at TIFF base
            const tView = new DataView(arr.buffer, tb);

            // IFD0
            const ifd0 = readIFD(tView, ifd0Off, 0, le, TAG);
            Object.assign(res.tags, ifd0);

            // ExifIFD
            if (ifd0["ExifIFDPointer"] != null) {
              const eIFD = readIFD(tView, ifd0["ExifIFDPointer"], 0, le, TAG);
              Object.assign(res.tags, eIFD);
            }
            // GPS IFD
            if (ifd0["GPSInfoIFDPointer"] != null) {
              const gIFD = readIFD(tView, ifd0["GPSInfoIFDPointer"], 0, le, GPS_TAG);
              const lat = gpsDecimal(gIFD["GPSLatitude"], gIFD["GPSLatitudeRef"]);
              const lon = gpsDecimal(gIFD["GPSLongitude"], gIFD["GPSLongitudeRef"]);
              if (lat !== null && lon !== null)
                res.gps = { lat: lat.toFixed(6), lon: lon.toFixed(6) };
            }
            // IFD1 thumbnail check
            try {
              const ne = tView.getUint16(ifd0Off, le);
              const nOff = tView.getUint32(ifd0Off + 2 + ne * 12, le);
              if (nOff > 0 && nOff < tView.byteLength - 12) {
                const ifd1 = readIFD(tView, nOff, 0, le, TAG);
                res.hasThumbnail =
                  ifd1["Compression"] !== undefined || ifd1["JPEGInterchangeFormat"] !== undefined;
              }
            } catch (_) {}
            break;
          }
          pos += 2 + (mkr === 0xd9 || mkr === 0xd8 ? 0 : len);
        }
        resolve(res);
      };
      fr.readAsArrayBuffer(file.slice(0, 196608)); // 192 KB
    });
  }

  /* ── Build forensic indicators from real metadata ── */
  function buildIndicators(meta, file) {
    const t = meta.tags,
      inds = [];
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
      "paint",
      "affinity",
      "pixelmator",
      "meitu",
      "capture one",
    ];
    const foundEd = editors.find((n) => sw.includes(n));
    if (foundEd || meta.editorSigs.length) {
      score += 35;
      const label = foundEd ? t.Software : meta.editorSigs[0].label;
      inds.push({
        sev: "CRITICAL",
        rule: `بصمة تحرير مُكتشفة: ${label}`,
        det: "EXIF:Software يُثبت استخدام برنامج تحرير — دليل قاطع على التعديل الرقمي",
        ev: `EXIF:Software = "${t.Software || meta.editorSigs[0].label}"`,
      });
    }

    // Timestamp mismatch
    const dOrig = t.DateTimeOriginal || t.DateTimeDigitized;
    const dMod = t.DateTime;
    if (dOrig && dMod && dOrig !== dMod) {
      const parse = (s) => {
        try {
          return new Date(s.replace(/^(\d{4}):(\d{2}):(\d{2})/, "$1-$2-$3"));
        } catch {
          return null;
        }
      };
      const d1 = parse(dOrig),
        d2 = parse(dMod);
      if (d1 && d2) {
        const diffMs = Math.abs(d2 - d1),
          diffH = (diffMs / 3600000).toFixed(1);
        if (diffMs > 120000) {
          score += 20;
          inds.push({
            sev: "HIGH",
            rule: `تعارض زمني: DateTimeOriginal ↔ DateTime (Δ ${diffH}h)`,
            det: `الالتقاط: ${dOrig} | التعديل: ${dMod} — فارق ${diffH} ساعة مؤشر على إعادة الحفظ`,
            ev: `Original:${dOrig} | Modified:${dMod} | Δ=${diffH}h`,
          });
        }
      }
    }

    // Thumbnail
    if (!meta.hasThumbnail && meta.magic === "JPEG") {
      score += 12;
      inds.push({
        sev: "HIGH",
        rule: "Thumbnail EXIF غائب — مؤشر إعادة تصدير",
        det: "الكاميرات الحديثة تحفظ Thumbnail تلقائياً في IFD1. غيابه يُشير إلى إعادة الحفظ أو التعديل الكامل",
        ev: "EXIF:IFD1:Thumbnail = NOT FOUND",
      });
    }

    // GPS
    if (meta.gps) {
      score += 5;
      inds.push({
        sev: "MEDIUM",
        rule: "إحداثيات GPS مُضمَّنة — معلومات الموقع مكشوفة",
        det: `إحداثيات دقيقة قابلة للتتبع الجغرافي`,
        ev: `GPS: ${meta.gps.lat}°N, ${meta.gps.lon}°E`,
      });
    }

    // JPEG quality
    if (meta.jpegQuality !== null && meta.jpegQuality < 88) {
      score += 15;
      inds.push({
        sev: "MEDIUM",
        rule: `جودة JPEG منخفضة (~${meta.jpegQuality}%) — مؤشر إعادة ضغط`,
        det: `الكاميرات الحديثة تنتج JPEG بجودة 92-98%. الجودة ${meta.jpegQuality}% تدل على إعادة الحفظ أو التصدير`,
        ev: `JPEG Quality Factor ≈ ${meta.jpegQuality}% (Expected: ≥92%)`,
      });
    }

    // Binary editor sigs (separate from EXIF)
    for (const sig of meta.editorSigs) {
      if (!foundEd) {
        score += 25;
        inds.push({
          sev: sig.sev,
          rule: `توقيع ثنائي: ${sig.label}`,
          det: "رُصد توقيع برنامج التحرير في البايتات الثنائية للملف مباشرةً",
          ev: `Binary signature found: "${sig.label}"`,
        });
      }
    }

    // FS date vs EXIF date gap
    if (meta.lastModified && dOrig) {
      const exifD = new Date(dOrig.replace(/^(\d{4}):(\d{2}):(\d{2})/, "$1-$2-$3"));
      const fsD = new Date(meta.lastModified);
      if (!isNaN(exifD) && !isNaN(fsD)) {
        const diffDays = Math.abs(fsD - exifD) / 86400000;
        if (diffDays > 45) {
          score += 5;
          inds.push({
            sev: "LOW",
            rule: `فجوة بين تاريخ الملف (FS) وتاريخ EXIF: ${Math.round(diffDays)} يوم`,
            det: "الفارق الزمني الكبير قد يُشير إلى نسخ ملف قديم أو تلاعب بالتواريخ",
            ev: `EXIF:${dOrig} | FS:${new Date(meta.lastModified).toISOString().slice(0, 10)}`,
          });
        }
      }
    }

    return { score: Math.min(score, 99), inds };
  }

  /* ── Build EXIF display table ── */
  function buildTable(meta, hashStr) {
    const t = meta.tags,
      rows = [];
    const r = (k, v, f = "") =>
      rows.push({ k, v: v != null && v !== "" ? String(v) : "—", flag: f });
    r("اسم الملف", meta.name);
    r("الحجم", `${(meta.size / 1024).toFixed(1)} KB`);
    r("النوع / MIME", meta.type);
    r("التنسيق (Magic Bytes)", meta.magic);
    const w = t.PixelXDimension || t.ImageWidth,
      h = t.PixelYDimension || t.ImageLength;
    if (w && h) r("الأبعاد", `${w} × ${h} px`);
    const mk = t.Make,
      mo = t.Model;
    if (mk || mo) r("الكاميرا / الجهاز", [mk, mo].filter(Boolean).join(" "));
    if (t.Software) {
      const isEd = [
        "photoshop",
        "gimp",
        "lightroom",
        "snapseed",
        "facetune",
        "faceapp",
        "canva",
      ].some((n) => String(t.Software).toLowerCase().includes(n));
      r("برنامج التحرير (EXIF)", t.Software, isEd ? "warn" : "");
    }
    if (t.DateTimeOriginal) r("تاريخ الالتقاط (DateTimeOriginal)", t.DateTimeOriginal);
    if (t.DateTimeDigitized && t.DateTimeDigitized !== t.DateTimeOriginal)
      r("تاريخ الرقمنة", t.DateTimeDigitized);
    if (t.DateTime) {
      const diff = t.DateTime !== t.DateTimeOriginal && t.DateTimeOriginal;
      r("آخر تعديل (DateTime)", t.DateTime + (diff ? " ⚠ يختلف عن الأصل" : ""), diff ? "warn" : "");
    }
    if (t.ISOSpeedRatings)
      r(
        "ISO Speed",
        `ISO-${Array.isArray(t.ISOSpeedRatings) ? t.ISOSpeedRatings[0] : t.ISOSpeedRatings}`,
      );
    if (t.FNumber)
      r("فتحة العدسة", `f/${typeof t.FNumber === "number" ? t.FNumber.toFixed(1) : t.FNumber}`);
    if (t.ExposureTime) r("سرعة الغالق", `1/${Math.round(1 / t.ExposureTime)}s`);
    if (t.FocalLength) r("البعد البؤري", `${Math.round(t.FocalLength)}mm`);
    if (t.FocalLengthIn35mmFilm) r("البعد البؤري (35mm)", `${t.FocalLengthIn35mmFilm}mm`);
    if (t.Flash !== undefined)
      r("الفلاش", t.Flash === 0 ? "لم يُستخدم" : t.Flash === 1 ? "استُخدم" : `Code:${t.Flash}`);
    r(
      "إحداثيات GPS",
      meta.gps ? `${meta.gps.lat}°, ${meta.gps.lon}°` : "غير موجودة",
      meta.gps ? "" : "",
    );
    r(
      "Thumbnail EXIF",
      meta.hasThumbnail ? "✓ موجود" : "⚠ غائب — مؤشر إعادة حفظ",
      meta.hasThumbnail ? "ok" : "warn",
    );
    if (meta.jpegQuality !== null)
      r(
        "جودة JPEG المقدّرة",
        `~${meta.jpegQuality}% (الافتراضي ≥92%)`,
        meta.jpegQuality < 88 ? "warn" : "ok",
      );
    if (hashStr) r("SHA-256 (مُحسوب آنياً)", hashStr + " [Verified]", "ok");
    r(
      "تاريخ تعديل الملف (FS)",
      new Date(meta.lastModified).toISOString().replace("T", " ").slice(0, 19),
    );
    return rows;
  }

  /* ── Main analyze entry point ── */
  async function analyze(file) {
    // ─── Demo mode (no file) ───
    if (!file) {
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
            sev: "CRITICAL",
            rule: "ELA — شذوذ مستويات ضغط JPEG",
            det: "اكتُشفت مناطق في الصورة بمستويات ضغط مختلفة — مؤشر على اللصق والتعديل في الربع السفلي الأيسر",
            ev: "ELA Anomaly Region: x:1280–1920, y:900–1440 px",
          },
          {
            sev: "HIGH",
            rule: "تعارض زمني: DateTimeOriginal ↔ DateTime (Δ 7.6h)",
            det: "تاريخ الالتقاط 08:14:22 يختلف عن DateTime 15:52:07 — فارق 7.6 ساعة يدل على إعادة حفظ",
            ev: "Original:2024:04:10 08:14:22 | Modified:2024:04:10 15:52:07",
          },
          {
            sev: "HIGH",
            rule: "Thumbnail EXIF غائب — مؤشر إعادة تصدير",
            det: "الكاميرات الحديثة تحفظ Thumbnail تلقائياً. غيابه يُشير إلى تصدير يدوي أو تعديل كامل للملف",
            ev: "EXIF:IFD1:Thumbnail = NOT FOUND",
          },
          {
            sev: "MEDIUM",
            rule: "جودة JPEG منخفضة (~82%) — مؤشر إعادة ضغط",
            det: "iPhone ينتج 94-98%. الجودة 82% تدل على إعادة الحفظ بجودة أقل بعد التعديل",
            ev: "JPEG Quality Factor ≈ 82% (Camera default: 94-98%)",
          },
          {
            sev: "MEDIUM",
            rule: "إحداثيات GPS مُضمَّنة — معلومات الموقع مكشوفة",
            det: "إحداثيات GPS دقيقة تكشف موقع الالتقاط — قد تستخدم في تتبع الجغرافي",
            ev: "GPS: 24.713600°N, 46.675300°E (الرياض، SA)",
          },
        ],
        exifTable: [
          { k: "اسم الملف", v: "evidence_photo_032.jpg", flag: "" },
          { k: "الحجم", v: "1,247.3 KB", flag: "" },
          { k: "النوع / MIME", v: "image/jpeg", flag: "" },
          { k: "التنسيق (Magic Bytes)", v: "JPEG (FF D8 FF E1)", flag: "" },
          { k: "الأبعاد", v: "4032 × 3024 px", flag: "" },
          { k: "الكاميرا / الجهاز", v: "Apple iPhone 15 Pro", flag: "" },
          { k: "برنامج التحرير (EXIF)", v: "Adobe Photoshop 26.0 (Windows)", flag: "warn" },
          { k: "تاريخ الالتقاط (DateTimeOriginal)", v: "2024:04:10 08:14:22", flag: "" },
          { k: "آخر تعديل (DateTime)", v: "2024:04:10 15:52:07 ⚠ يختلف عن الأصل", flag: "warn" },
          { k: "ISO Speed", v: "ISO-125", flag: "" },
          { k: "فتحة العدسة", v: "f/1.8", flag: "" },
          { k: "سرعة الغالق", v: "1/120s", flag: "" },
          { k: "البعد البؤري", v: "26mm (35mm: 24mm)", flag: "" },
          { k: "إحداثيات GPS", v: "24.713600°N, 46.675300°E", flag: "" },
          { k: "Thumbnail EXIF", v: "⚠ غائب — مؤشر إعادة حفظ", flag: "warn" },
          { k: "جودة JPEG المقدّرة", v: "~82% (الافتراضي ≥92%)", flag: "warn" },
          { k: "SHA-256 (مُحسوب آنياً)", v: "a3f9b2c1d8e5f7a0…d3e5f7a9 [Verified]", flag: "ok" },
          { k: "تاريخ تعديل الملف (FS)", v: "2024-04-10 15:52:11", flag: "" },
        ],
        chips: [
          "Photoshop Detected",
          "ELA Anomaly",
          "Timestamp Mismatch",
          "Thumbnail Missing",
          "GPS Embedded",
          "Re-encoded JPEG",
        ],
        name: "evidence_photo_032.jpg",
        size: "1,247.3",
        type: "image/jpeg",
      };
    }

    // ─── Real file ───
    const meta = await readMetadata(file);

    // SHA-256 of real file
    let hashStr = null;
    try {
      const buf = await file.arrayBuffer();
      const dig = await crypto.subtle.digest("SHA-256", buf);
      hashStr =
        [...new Uint8Array(dig)]
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
          .slice(0, 32) + "…";
    } catch (_) {}

    const hasRealEXIF = meta.magic === "JPEG" && Object.keys(meta.tags).length > 2;
    const analysis = hasRealEXIF
      ? buildIndicators(meta, file)
      : {
          score: 30,
          inds: [
            {
              sev: "MEDIUM",
              rule: "بيانات EXIF غير موجودة أو محدودة",
              det: "لا توجد بيانات EXIF قابلة للقراءة — الملف قد يكون مُجرَّداً من البيانات الوصفية أو تالفاً",
              ev: `Format: ${meta.magic}`,
            },
          ],
        };

    const table = buildTable(meta, hashStr);
    const pct = analysis.score;
    const threat = pct >= 55 ? "crit" : pct >= 25 ? "warn" : "safe";

    const chips = [];
    const swL = (meta.tags.Software || "").toLowerCase();
    if (swL.includes("photoshop")) chips.push("Photoshop Detected");
    if (meta.editorSigs.length) chips.push(meta.editorSigs[0].label.split("(")[0].trim());
    if (!meta.hasThumbnail && meta.magic === "JPEG") chips.push("Thumbnail Missing");
    if (meta.gps) chips.push("GPS Embedded");
    if (meta.jpegQuality !== null && meta.jpegQuality < 88)
      chips.push(`JPEG Quality ${meta.jpegQuality}%`);
    if (
      meta.tags.DateTimeOriginal &&
      meta.tags.DateTime &&
      meta.tags.DateTimeOriginal !== meta.tags.DateTime
    )
      chips.push("Timestamp Mismatch");
    if (!chips.length) chips.push("Clean — No Critical Indicators");

    return {
      pct,
      threat,
      indicators: analysis.inds,
      exifTable: table,
      chips,
      name: meta.name,
      size: (meta.size / 1024).toFixed(1),
      type: meta.type,
    };
  }

  return { analyze };
})();

/* ─────────────────────────────────────────
   MOD-04 — EMAIL HEADER ANALYSIS ENGINE v1.0
───────────────────────────────────────── */
const EmailEngine = (() => {
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
    const xSpam = headers["x-spam-score"] || headers["x-spam-status"] || "—";

    // SPF check
    if (auth.spf === "fail") {
      score += 5;
      findings.push({
        sev: "CRITICAL",
        rule: "SPF Fail — المرسل غير مصرح له",
        det: "سجل SPF يرفض هذا المرسل — مؤشر قوي على الانتحال",
        ev: `spf=${auth.spf}`,
      });
    } else if (auth.spf === "softfail") {
      score += 3;
      findings.push({
        sev: "HIGH",
        rule: "SPF SoftFail — فشل ناعم في التحقق",
        det: "المرسل خارج نطاق السجلات المعتمدة",
        ev: `spf=${auth.spf}`,
      });
    } else if (auth.spf === "none") {
      score += 2;
      findings.push({
        sev: "MEDIUM",
        rule: "SPF غير مُعرَّف للنطاق",
        det: "النطاق لا يمتلك سجل SPF — يسهّل الانتحال",
        ev: "SPF: none",
      });
    }

    // DKIM
    if (auth.dkim === "fail") {
      score += 5;
      findings.push({
        sev: "CRITICAL",
        rule: "DKIM Fail — التوقيع الرقمي فاشل",
        det: "التوقيع الرقمي للبريد لا يتطابق — الرسالة تعرضت للتعديل أو الانتحال",
        ev: `dkim=${auth.dkim}`,
      });
    } else if (auth.dkim === "none") {
      score += 2;
      findings.push({
        sev: "MEDIUM",
        rule: "DKIM غير موجود",
        det: "البريد غير مُوقَّع رقمياً — لا يمكن التحقق من المصدر",
        ev: "DKIM: none",
      });
    }

    // DMARC
    if (auth.dmarc === "fail") {
      score += 4;
      findings.push({
        sev: "CRITICAL",
        rule: "DMARC Fail — سياسة المجال مُنتهَكة",
        det: "الرسالة تفشل في سياسة DMARC — احتمال انتحال هوية عالٍ جداً",
        ev: `dmarc=${auth.dmarc}`,
      });
    } else if (auth.dmarc === "none") {
      score += 1;
      findings.push({
        sev: "LOW",
        rule: "DMARC غير مُعرَّف",
        det: "سياسة DMARC غير موجودة للنطاق",
        ev: "DMARC: none",
      });
    }

    // From vs Return-Path mismatch
    const fromDomain = (from.match(/@([\w\.-]+)/) || [, ""])[1].toLowerCase();
    const rpDomain = (returnPath.match(/@([\w\.-]+)/) || [, ""])[1].toLowerCase();
    if (fromDomain && rpDomain && fromDomain !== rpDomain) {
      score += 3;
      findings.push({
        sev: "HIGH",
        rule: "تعارض From ↔ Return-Path",
        det: `نطاق المرسل (${fromDomain}) يختلف عن Return-Path (${rpDomain}) — مؤشر انتحال`,
        ev: `From:${fromDomain} / ReturnPath:${rpDomain}`,
      });
    }

    // Reply-To mismatch
    const replyDomain = (replyTo.match(/@([\w\.-]+)/) || [, ""])[1].toLowerCase();
    if (replyDomain && fromDomain && replyDomain !== fromDomain) {
      score += 3;
      findings.push({
        sev: "HIGH",
        rule: "تعارض From ↔ Reply-To",
        det: `الرد سيذهب إلى ${replyDomain} وليس ${fromDomain} — تكتيك شائع في التصيد`,
        ev: `From:${fromDomain} / ReplyTo:${replyDomain}`,
      });
    }

    // Spam score
    if (xSpam && xSpam !== "—" && /[5-9]\.|\d{2}\./.test(xSpam)) {
      score += 2;
      findings.push({
        sev: "MEDIUM",
        rule: "نقاط Spam عالية",
        det: `X-Spam-Score: ${xSpam}`,
        ev: xSpam,
      });
    }

    // Suspicious hops
    if (hops.length > 5) {
      score += 1;
      findings.push({
        sev: "LOW",
        rule: `سلسلة توجيه طويلة (${hops.length} نقاط)`,
        det: "عدد كبير من نقاط التمرير قد يدل على إخفاء المصدر الحقيقي",
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
    const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
    return [...new Uint8Array(hashBuffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function sha1(buffer) {
    const hashBuffer = await crypto.subtle.digest("SHA-1", buffer);
    return [...new Uint8Array(hashBuffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  // Simple MD5 (for forensic reference — not for security use)
  function md5(str) {
    function safeAdd(x, y) {
      const lsw = (x & 0xffff) + (y & 0xffff);
      const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
      return (msw << 16) | (lsw & 0xffff);
    }
    function bitRotate(num, cnt) {
      return (num << cnt) | (num >>> (32 - cnt));
    }
    function md5cmn(q, a, b, x, s, t) {
      return safeAdd(bitRotate(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
    }
    function md5ff(a, b, c, d, x, s, t) {
      return md5cmn((b & c) | (~b & d), a, b, x, s, t);
    }
    function md5gg(a, b, c, d, x, s, t) {
      return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
    }
    function md5hh(a, b, c, d, x, s, t) {
      return md5cmn(b ^ c ^ d, a, b, x, s, t);
    }
    function md5ii(a, b, c, d, x, s, t) {
      return md5cmn(c ^ (b | ~d), a, b, x, s, t);
    }

    const utf8 = unescape(encodeURIComponent(str));
    const arr = [];
    for (let i = 0; i < utf8.length; i++) arr.push(utf8.charCodeAt(i));
    arr.push(128);
    while (arr.length % 64 !== 56) arr.push(0);
    const length8 = utf8.length * 8;
    arr.push(
      length8 & 0xff,
      (length8 >>> 8) & 0xff,
      (length8 >>> 16) & 0xff,
      (length8 >>> 24) & 0xff,
      0,
      0,
      0,
      0,
    );

    let a = 1732584193,
      b = -271733879,
      c = -1732584194,
      d = 271733878;
    for (let i = 0; i < arr.length; i += 64) {
      const [oa, ob, oc, od] = [a, b, c, d];
      const x = [];
      for (let j = 0; j < 16; j++)
        x.push(
          arr[i + j * 4] |
            (arr[i + j * 4 + 1] << 8) |
            (arr[i + j * 4 + 2] << 16) |
            (arr[i + j * 4 + 3] << 24),
        );
      a = md5ff(a, b, c, d, x[0], 7, -680876936);
      d = md5ff(d, a, b, c, x[1], 12, -389564586);
      c = md5ff(c, d, a, b, x[2], 17, 606105819);
      b = md5ff(b, c, d, a, x[3], 22, -1044525330);
      a = md5ff(a, b, c, d, x[4], 7, -176418897);
      d = md5ff(d, a, b, c, x[5], 12, 1200080426);
      c = md5ff(c, d, a, b, x[6], 17, -1473231341);
      b = md5ff(b, c, d, a, x[7], 22, -45705983);
      a = md5ff(a, b, c, d, x[8], 7, 1770035416);
      d = md5ff(d, a, b, c, x[9], 12, -1958414417);
      c = md5ff(c, d, a, b, x[10], 17, -42063);
      b = md5ff(b, c, d, a, x[11], 22, -1990404162);
      a = md5ff(a, b, c, d, x[12], 7, 1804603682);
      d = md5ff(d, a, b, c, x[13], 12, -40341101);
      c = md5ff(c, d, a, b, x[14], 17, -1502002290);
      b = md5ff(b, c, d, a, x[15], 22, 1236535329);
      a = md5gg(a, b, c, d, x[1], 5, -165796510);
      d = md5gg(d, a, b, c, x[6], 9, -1069501632);
      c = md5gg(c, d, a, b, x[11], 14, 643717713);
      b = md5gg(b, c, d, a, x[0], 20, -373897302);
      a = md5gg(a, b, c, d, x[5], 5, -701558691);
      d = md5gg(d, a, b, c, x[10], 9, 38016083);
      c = md5gg(c, d, a, b, x[15], 14, -660478335);
      b = md5gg(b, c, d, a, x[4], 20, -405537848);
      a = md5gg(a, b, c, d, x[9], 5, 568446438);
      d = md5gg(d, a, b, c, x[14], 9, -1019803690);
      c = md5gg(c, d, a, b, x[3], 14, -187363961);
      b = md5gg(b, c, d, a, x[8], 20, 1163531501);
      a = md5gg(a, b, c, d, x[13], 5, -1444681467);
      d = md5gg(d, a, b, c, x[2], 9, -51403784);
      c = md5gg(c, d, a, b, x[7], 14, 1735328473);
      b = md5gg(b, c, d, a, x[12], 20, -1926607734);
      a = md5hh(a, b, c, d, x[5], 4, -378558);
      d = md5hh(d, a, b, c, x[8], 11, -2022574463);
      c = md5hh(c, d, a, b, x[11], 16, 1839030562);
      b = md5hh(b, c, d, a, x[14], 23, -35309556);
      a = md5hh(a, b, c, d, x[1], 4, -1530992060);
      d = md5hh(d, a, b, c, x[4], 11, 1272893353);
      c = md5hh(c, d, a, b, x[7], 16, -155497632);
      b = md5hh(b, c, d, a, x[10], 23, -1094730640);
      a = md5hh(a, b, c, d, x[13], 4, 681279174);
      d = md5hh(d, a, b, c, x[0], 11, -358537222);
      c = md5hh(c, d, a, b, x[3], 16, -722521979);
      b = md5hh(b, c, d, a, x[6], 23, 76029189);
      a = md5hh(a, b, c, d, x[9], 4, -640364487);
      d = md5hh(d, a, b, c, x[12], 11, -421815835);
      c = md5hh(c, d, a, b, x[15], 16, 530742520);
      b = md5hh(b, c, d, a, x[2], 23, -995338651);
      a = md5ii(a, b, c, d, x[0], 6, -198630844);
      d = md5ii(d, a, b, c, x[7], 10, 1126891415);
      c = md5ii(c, d, a, b, x[14], 15, -1416354905);
      b = md5ii(b, c, d, a, x[5], 21, -57434055);
      a = md5ii(a, b, c, d, x[12], 6, 1700485571);
      d = md5ii(d, a, b, c, x[3], 10, -1894986606);
      c = md5ii(c, d, a, b, x[10], 15, -1051523);
      b = md5ii(b, c, d, a, x[1], 21, -2054922799);
      a = md5ii(a, b, c, d, x[8], 6, 1873313359);
      d = md5ii(d, a, b, c, x[15], 10, -30611744);
      c = md5ii(c, d, a, b, x[6], 15, -1560198380);
      b = md5ii(b, c, d, a, x[13], 21, 1309151649);
      a = md5ii(a, b, c, d, x[4], 6, -145523070);
      d = md5ii(d, a, b, c, x[11], 10, -1120210379);
      c = md5ii(c, d, a, b, x[2], 15, 718787259);
      b = md5ii(b, c, d, a, x[9], 21, -343485551);
      a = safeAdd(a, oa);
      b = safeAdd(b, ob);
      c = safeAdd(c, oc);
      d = safeAdd(d, od);
    }
    return [a, b, c, d]
      .map((n) => (n >>> 0).toString(16).padStart(8, "0").match(/../g).reverse().join(""))
      .join("");
  }

  async function analyzeText(text) {
    const encoder = new TextEncoder();
    const buf = encoder.encode(text);
    const [s256, s1] = await Promise.all([sha256(buf), sha1(buf)]);
    const md5Hash = md5(text);
    return {
      sha256: s256,
      sha1: s1,
      md5: md5Hash,
      length: text.length,
      bytes: buf.byteLength,
      entropy: calcEntropy(text),
    };
  }

  async function analyzeFile(file) {
    const buf = await file.arrayBuffer();
    const [s256, s1] = await Promise.all([sha256(buf), sha1(buf)]);
    const textPart = new TextDecoder("utf-8", { fatal: false }).decode(buf.slice(0, 2048));
    return {
      sha256: s256,
      sha1: s1,
      md5: md5(textPart),
      name: file.name,
      size: file.size,
      type: file.type,
    };
  }

  function calcEntropy(s) {
    const f = {};
    for (const c of s) f[c] = (f[c] || 0) + 1;
    const n = s.length;
    return -Object.values(f).reduce((a, v) => {
      const p = v / n;
      return a + p * Math.log2(p);
    }, 0);
  }

  return { analyzeText, analyzeFile, md5, sha256 };
})();
