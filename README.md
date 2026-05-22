# 🛡️ DFAS v2 — Digital Forensics Analysis System

**نظام التحليل الجنائي للجرائم الرقمية — الإصدار الثاني**

مشروع تخرج · دبلوم الأمن السيبراني | TLP:AMBER | ISO/IEC 27037:2012

---

## هيكل المشروع

```
DFAS-Digital/
├── index.html          # المنصة الرئيسية الكاملة
├── src/
│   ├── dfas-db.js      # Backend — قاعدة بيانات IndexedDB
│   ├── dfas-engines.js # Analysis Engines MOD-01 → MOD-16
│   ├── dfas-charts.js  # SVG + Canvas Charts
│   └── dfas-ui.js      # UI Controller + Dashboard
└── docs/ · tests/ · reports/
```

## المحركات (المنفذة + خارطة التطوير)

| | المحرك | الوصف |
|-|--------|-------|
| MOD-01 | كاشف التصيد | 47 مؤشر لغوي في 9 فئات |
| MOD-02 | محلل الروابط | 13 معيار + Shannon Entropy |
| MOD-03 | جنائيات الصور | EXIF/XMP + ELA Analysis |
| MOD-04 | ترويسات البريد | SPF/DKIM/DMARC |
| MOD-05 | البصمة الرقمية | SHA-256 / SHA-1 / MD5 |

## التشغيل

افتح `index.html` مباشرة في المتصفح — لا خادم ولا إنترنت مطلوب.

تمت إضافة Motion Graphic تفاعلية في الصفحة الرئيسية + خارطة تطوير لمحركات MOD-11 → MOD-16.

## التقنيات

- Frontend: HTML5/CSS3/JS ES2022
- Database: IndexedDB (Persistent, Local)
- Crypto: Web Crypto API
- Charts: SVG + Canvas (No libraries)
- Standards: ISO 27037 · NIST 800-86 · RFC 3227

⚠️ للأغراض التعليمية والبحثية فقط · TLP:AMBER
