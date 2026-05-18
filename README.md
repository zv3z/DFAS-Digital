# 🛡️ DFAS — Digital Forensics Analysis System 
### نظام التحليل الجنائي للجرائم الرقمية

<div align="center">

![DFAS Banner](assets/banner.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Standard: ISO 27037](https://img.shields.io/badge/Standard-ISO%2FIEC%2027037%3A2012-green.svg)](https://www.iso.org/standard/44381.html)
[![Standard: NIST](https://img.shields.io/badge/Standard-NIST%20SP%20800--86-orange.svg)](https://csrc.nist.gov/publications/detail/sp/800-86/final)
[![TLP](https://img.shields.io/badge/TLP-AMBER-yellow.svg)]()
[![Status](https://img.shields.io/badge/Status-Academic%20Project-purple.svg)]()

**مشروع تخرج — دبلوم الأمن السيبراني | Cybersecurity Diploma Graduation Project**

</div>

---

## 📋 نبذة عن المشروع | Overview

**DFAS** هو نظام تحليل جنائي رقمي متكامل يعمل بالكامل بدون اتصال بالإنترنت (Offline-First)، مُصمَّم لكشف وتحليل جرائم الاحتيال الإلكتروني. يجمع ثلاثة محركات تحليل سيبراني في منصة واحدة ذات واجهة عربية كاملة، مع إنتاج تقارير جنائية رقمية موثقة وفق معيار ISO/IEC 27037:2012.

> **DFAS** is a comprehensive digital forensics analysis system that operates fully offline (Offline-First), designed to detect and analyze electronic fraud crimes. It combines three cybersecurity analysis engines in a single platform with a full Arabic interface, producing digital forensic reports compliant with ISO/IEC 27037:2012.

---

## ✨ الميزات الرئيسية | Key Features

| الميزة | الوصف |
|--------|-------|
| 📨 **MOD-01** كاشف التصيد | 47 مؤشر لغوي وسلوكي في 9 فئات كشف |
| 🔗 **MOD-02** محلل الروابط | 13 معيار أمني + Shannon Entropy لكشف DGA |
| 🖼 **MOD-03** جنائيات الصور | EXIF/XMP + ELA Analysis + 7 مؤشرات تزوير |
| 📊 **CTRL** لوحة القيادة | سجل عمليات حي + تقارير ISO 27037 تلقائية |
| 🔒 **Offline-First** | لا ترسل أي بيانات خارجياً — خصوصية كاملة |
| 🌐 **عربي كاملاً** | الأول من نوعه بواجهة عربية متكاملة |

---

## 🔬 المحركات التقنية | Technical Engines

### MOD-01 — Phishing Detection Engine
```
محرك كشف التصيد الاحتيالي
├── 9 فئات تحليل: استعجال، انتحال هوية، طلب بيانات، إغراء مالي...
├── 47 مؤشر لغوي وسلوكي
├── تحليل الروابط المضمنة في النص
├── كشف الخلط اللغوي (عربي/لاتيني)
└── تحليل علامات الترقيم المفرطة
```

### MOD-02 — URL Analysis Engine
```
محرك تحليل الروابط الخبيثة
├── 13 معيار أمني: TLD، IP مباشر، Typosquatting...
├── Shannon Entropy لكشف نطاقات DGA
├── Open Redirect Detection
├── Percent-Encoding Analysis
├── Non-Standard Port Detection
└── URL Component Decomposition
```

### MOD-03 — Image Forensics Engine
```
محرك الجنائيات الرقمية للصور
├── EXIF/XMP Metadata Extraction
├── Error Level Analysis (ELA)
├── Photoshop Signature Detection
├── EXIF ↔ XMP Timestamp Conflict
├── JPEG Quality Factor Analysis
├── Thumbnail Integrity Check
└── SHA-256 / MD5 Verification
```

---

## 🛠️ التقنيات المستخدمة | Technologies

```
Frontend:   HTML5 / CSS3 / JavaScript ES2022
Analysis:   Shannon Entropy Algorithm
            Error Level Analysis (ELA)
            EXIF/XMP Metadata Parsing
            Multi-layer Rule Engine
Standards:  ISO/IEC 27037:2012
            NIST SP 800-86
            RFC 3227
            ACPO Digital Evidence Guidelines v5
Security:   CSP Headers
            X-Frame-Options: DENY
            X-Content-Type-Options: nosniff
            Input Sanitization (XSS Prevention)
            Offline-First (No External Requests)
```

---

## 📁 هيكل المشروع | Project Structure

```
DFAS/
├── src/
│   └── DFAS-platform.html      # النظام الرئيسي — Main System
├── docs/
│   ├── DFAS_Project_Proposal.pdf   # مقترح المشروع الكامل
│   └── DFAS_Presentation.pptx      # عرض تقديمي للمعلمين
├── assets/
│   └── screenshots/            # لقطات الشاشة
├── tests/
│   └── test-cases.md           # حالات الاختبار الموثقة
├── reports/
│   └── sample-report.md        # نموذج تقرير جنائي
├── README.md
├── LICENSE
├── SECURITY.md
└── .gitignore
```

---

## 🚀 طريقة التشغيل | Getting Started

### متطلبات التشغيل | Requirements
- متصفح حديث (Chrome 90+ / Firefox 88+ / Edge 90+)
- لا يتطلب إنترنت
- لا يتطلب تثبيتاً

### تشغيل المشروع | Run Locally
```bash
# 1. استنساخ المستودع
git clone https://github.com/YOUR_USERNAME/DFAS-Digital-Forensics-Analysis-System.git

# 2. الانتقال لمجلد المشروع
cd DFAS-Digital-Forensics-Analysis-System

# 3. فتح الملف مباشرة في المتصفح
# macOS
open src/DFAS-platform.html

# Windows
start src/DFAS-platform.html

# Linux
xdg-open src/DFAS-platform.html
```

> ⚡ **بديل سريع:** يمكن فتح الملف مباشرة بالضغط المزدوج عليه

---

## 📊 نتائج الأداء | Performance Results

| المحرك | الدقة | المعيار المرجعي |
|--------|-------|-----------------|
| MOD-01 كشف التصيد | **89%** | اختبار على 50 رسالة |
| MOD-02 تحليل URL | **92%** | اختبار على 50 رابطاً |
| MOD-03 جنائيات الصور | **85%** | اختبار على 50 وثيقة |
| زمن الاستجابة | **< 3s** | جهاز متوسط المواصفات |

---

## 🔒 الأمان والأخلاقيات | Security & Ethics

```
⚠️  تحذير مهم — Important Warning
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
هذا المشروع مُعدّ للأغراض التعليمية والبحثية فقط.
This project is for educational and research purposes ONLY.

✅ جميع الاختبارات في بيئة VM معزولة
✅ لا ترسل بيانات لأي خادم خارجي
✅ لا يُستخدم لاختراق أنظمة حقيقية
✅ البيانات المستخدمة افتراضية وتعليمية
✅ الالتزام بأخلاقيات الأمن السيبراني

التصنيف: TLP:AMBER — للاستخدام الأكاديمي المقيد
```

---

## 📐 المعايير المعتمدة | Compliance Standards

| المعيار | الجهة | الاستخدام |
|---------|-------|-----------|
| ISO/IEC 27037:2012 | ISO | توثيق الأدلة الرقمية |
| NIST SP 800-86 | NIST | منهجية التحقيق الجنائي |
| RFC 3227 | IETF | جمع الأدلة وأرشفتها |
| ACPO Guidelines v5 | ACPO | إرشادات الأدلة الرقمية |

---

## 📚 المراجع العلمية | References

```
[1] NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response, 2006.
[2] ISO/IEC 27037:2012: Guidelines for Identification, Collection, Acquisition and
    Preservation of Digital Evidence.
[3] RFC 3227: Guidelines for Evidence Collection and Archiving, IETF, 2002.
[4] ACPO: Good Practice Guide for Digital Evidence, Version 5, 2012.
[5] Hutchings et al.: Cybercrime and Online Fraud Detection Systems Review, IEEE, 2021.
[6] Aburrous et al.: Intelligent Phishing Website Detection Using Fuzzy Techniques,
    Expert Systems with Applications, 2010.
[7] Shannon, C.E.: A Mathematical Theory of Communication, Bell System Technical
    Journal, 1948.
```

---

## 🗺️ خارطة التطوير | Roadmap

```
v1.0 ✅ الحالي
├── 3 محركات تحليل
├── 47 مؤشر كشف
├── تقارير ISO 27037
└── واجهة عربية كاملة

v2.0 🔄 قريباً
├── Email Header Analysis (SPF/DKIM/DMARC)
├── Blocklists محلية (PhishTank/URLhaus)
├── WHOIS Domain Age Check
└── Clone Detection للصور

v3.0 🔮 مستقبلي
├── AraBERT NLP Model
├── SIEM Integration (STIX/TAXII)
├── Case Management System
└── Government Cloud Deployment
```

---

## 👨‍💻 المساهمة | Contributing

المساهمات مرحب بها! يرجى:
1. Fork المستودع
2. إنشاء Branch جديد: `git checkout -b feature/your-feature`
3. Commit التغييرات: `git commit -m 'Add: your feature'`
4. Push: `git push origin feature/your-feature`
5. فتح Pull Request

---

## 📄 الترخيص | License

هذا المشروع مرخص تحت [MIT License](LICENSE).

---

## 📞 التواصل | Contact

> **مشروع تخرج — دبلوم الأمن السيبراني 2025**
>
> للاستفسارات الأكاديمية يمكن فتح [Issue](../../issues) في هذا المستودع.

---

<div align="center">

**⭐ إذا أفادك المشروع، لا تنسَ النجمة! | Star if you find it useful!**

`NIST SP 800-86` · `ISO/IEC 27037:2012` · `RFC 3227` · `ACPO Guidelines` · `TLP:AMBER`

</div>
