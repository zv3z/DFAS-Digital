# 🛡️ DFAS v3 — Digital Forensics Analysis System

**نظام التحليل الجنائي للجرائم الرقمية — الإصدار الثالث**

> دمج محركات DFAS-Digital الحقيقية مع واجهة void-detective الحديثة (React + TypeScript + TanStack)

---

## 🏗️ بنية المشروع

```
src/
├── engines/              ← محركات التحليل الحقيقية (مدمجة من DFAS-Digital)
│   ├── dfas-core.ts      ← MOD-01 → MOD-10 (10 محركات تحليل)
│   ├── runner.ts         ← موحّد التشغيل: slug → نتيجة مُعيّرة
│   ├── types.ts          ← TypeScript interfaces لجميع النتائج
│   └── index.ts          ← صادرات موحدة
│
├── routes/               ← صفحات TanStack Router
│   ├── index.tsx         ← الصفحة الرئيسية
│   ├── dashboard.tsx     ← لوحة التحكم
│   ├── modules.$slug.tsx ← صفحة التحليل (مُوصَّلة بالمحركات الحقيقية)
│   ├── cases.tsx         ← إدارة القضايا
│   └── about.tsx         ← عن المشروع
│
├── components/
│   ├── dfas/             ← مكونات DFAS المتخصصة (Sidebar, TopBar, UI)
│   └── ui/               ← shadcn/ui (46 مكون)
│
└── lib/
    ├── dfas-data.ts      ← تعريفات الوحدات (MODULES, NAV)
    └── utils.ts          ← أدوات مساعدة
```

---

## ⚙️ المحركات المُدمجة

| Module | Slug | المحرك | نوع المدخل |
|--------|------|--------|------------|
| MOD-01 | phishing | PhishingEngine | نص عربي |
| MOD-02 | url | UrlEngine | رابط URL |
| MOD-03 | image | ImageEngine* | صورة |
| MOD-04 | email | EmailEngine | ترويسات بريد |
| MOD-05 | fingerprint | HashEngine | ملف |
| MOD-06 | ioc | IOCEngine | نص |
| MOD-07 | stego | StegoEngine* | صورة |
| MOD-08 | timeline | TimelineEngine | نص/سجلات |
| MOD-09 | network | NetLogEngine | سجل شبكة |
| MOD-10 | mitre | ATTACKEngine | نص |

> \* MOD-03 و MOD-07 يحتاجان Canvas API (تعمل في المتصفح مباشرة)

---

## 🚀 التشغيل

```bash
# التثبيت
npm install

# تشغيل خادم التطوير
npm run dev
# → http://localhost:8080

# البناء للإنتاج
npm run build
```

---

## 🔗 مصادر الدمج

- **void-detective** (UI): React 19 + TanStack Router + Tailwind v4 + shadcn/ui
- **DFAS-Digital** (Engines): 47 مؤشر تصيد · EXIF Parser · Shannon Entropy · MITRE ATT&CK

---

## 📋 التصنيف

**TLP:AMBER** · للأغراض التعليمية والبحثية فقط · ISO/IEC 27037:2012
