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


| | المحرك | الوصف |
|-|--------|-------|
| MOD-01 | كاشف التصيد | 47 مؤشر لغوي في 9 فئات |
| MOD-02 | محلل الروابط | 13 معيار + Shannon Entropy |
| MOD-03 | جنائيات الصور | EXIF/XMP + ELA Analysis |
| MOD-04 | ترويسات البريد | SPF/DKIM/DMARC |
| MOD-05 | البصمة الرقمية | SHA-256 / SHA-1 / MD5 |
| MOD-06 | كاشف IOC | مؤشرات اختراق + Regex + Risk Score |
| MOD-07 | كاشف الإخفاء | LSB/Chi-Square/Entropy |
| MOD-08 | الخط الزمني الرقمي | استخراج timestamps وكشف الشذوذ |
| MOD-09 | تحليل سجلات الشبكة | Apache/Nginx/Syslog + Anomaly Detection |
| MOD-10 | MITRE ATT&CK Mapper | Mapping للتكتيكات والتقنيات |

## التشغيل

افتح `index.html` مباشرة في المتصفح — لا خادم ولا إنترنت مطلوب.

## التقنيات

- Frontend: HTML5/CSS3/JS ES2022
- Database: IndexedDB (Persistent, Local)
- Crypto: Web Crypto API
- Charts: SVG + Canvas (No libraries)
- Standards: ISO 27037 · NIST 800-86 · RFC 3227

⚠️ للأغراض التعليمية والبحثية فقط · TLP:AMBER
