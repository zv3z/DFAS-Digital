export type ModuleId =
  | "mod-01" | "mod-02" | "mod-03" | "mod-04" | "mod-05"
  | "mod-06" | "mod-07" | "mod-08" | "mod-09" | "mod-10";

export interface ModuleDef {
  id: ModuleId;
  code: string;
  slug: string;
  icon: string;
  nameAr: string;
  descAr: string;
  inputType: "text" | "url" | "image" | "file" | "headers" | "log";
  placeholder?: string;
}

export const MODULES: ModuleDef[] = [
  { id: "mod-01", code: "MOD-01", slug: "phishing", icon: "🔍", nameAr: "كاشف التصيد الاحتيالي", descAr: "تحليل محتوى الرسائل العربية لاكتشاف محاولات التصيد", inputType: "text", placeholder: "الصق نص البريد أو الرسالة هنا..." },
  { id: "mod-02", code: "MOD-02", slug: "url",      icon: "🔗", nameAr: "محلل الروابط",            descAr: "فحص الروابط وفق 13 معياراً أمنياً متقدماً", inputType: "url",  placeholder: "https://example.com/..." },
  { id: "mod-03", code: "MOD-03", slug: "image",    icon: "🖼️", nameAr: "الطب الشرعي للصور",       descAr: "استخراج EXIF واكتشاف التعديل الرقمي على الصور", inputType: "image" },
  { id: "mod-04", code: "MOD-04", slug: "email",    icon: "📧", nameAr: "ترويسات البريد",          descAr: "التحقق من SPF / DKIM / DMARC وأصل الرسالة", inputType: "headers", placeholder: "Received: from ...\nFrom: ...\nDKIM-Signature: ..." },
  { id: "mod-05", code: "MOD-05", slug: "fingerprint", icon: "🔐", nameAr: "البصمة الرقمية",       descAr: "حساب SHA-256 / SHA-1 / MD5 ومقارنة البصمات", inputType: "file" },
  { id: "mod-06", code: "MOD-06", slug: "ioc",      icon: "🎯", nameAr: "ماسح مؤشرات الاختراق",    descAr: "استخراج عناوين IP والنطاقات والبصمات والعملات", inputType: "text", placeholder: "الصق النص لاستخراج IOCs..." },
  { id: "mod-07", code: "MOD-07", slug: "stego",    icon: "🔒", nameAr: "كاشف الإخفاء (Steganography)", descAr: "تحليل LSB لاكتشاف البيانات المخفية في الصور", inputType: "image" },
  { id: "mod-08", code: "MOD-08", slug: "timeline", icon: "⏱",  nameAr: "الخط الزمني الرقمي",      descAr: "استخراج الأختام الزمنية وكشف الشذوذ", inputType: "text", placeholder: "الصق السجلات أو ارفع ملفاً..." },
  { id: "mod-09", code: "MOD-09", slug: "network",  icon: "🌐", nameAr: "محلل سجلات الشبكة",       descAr: "تحليل سجلات Apache / Nginx بشكل تلقائي", inputType: "text", placeholder: "الصق سجلات Apache / Nginx هنا...\n192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] \"GET / HTTP/1.1\" 200 1234" },
  { id: "mod-10", code: "MOD-10", slug: "mitre",    icon: "🎯", nameAr: "خريطة MITRE ATT&CK",      descAr: "تعيين السلوك على إطار MITRE ATT&CK", inputType: "text", placeholder: "صف السلوك أو الصق التقرير..." },
];

export const NAV = [
  { to: "/",          label: "الرئيسية",   icon: "⌂" },
  { to: "/dashboard", label: "لوحة التحكم", icon: "▦" },
  { to: "/modules",   label: "الوحدات",    icon: "◈" },
  { to: "/cases",     label: "القضايا",    icon: "⛬" },
  { to: "/about",     label: "حول النظام", icon: "ⓘ" },
] as const;
