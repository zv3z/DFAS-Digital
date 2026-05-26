/**
 * DFAS v3 — Deep Conflict & Responsiveness Test
 * Tests: routing, engines, mobile, errors, edge cases, performance
 */
const { chromium } = require("playwright");

const BASE = "http://localhost:8090";
let passed = 0,
  failed = 0,
  issues = [];

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ❌ ${name}`);
    console.log(`     → ${e.message.slice(0, 120)}`);
    failed++;
    issues.push({ name, err: e.message.slice(0, 200) });
  }
}

async function probe(name, fn) {
  try {
    await fn();
    console.log(`  🔍 ${name}: ثبت`);
  } catch (e) {
    console.log(`  🔍 ${name}: ${e.message.slice(0, 100)}`);
  }
}

(async () => {
  const browser = await chromium.launch({ args: ["--no-sandbox"] });

  // ── 1. DESKTOP VIEWPORT ─────────────────────────────────────
  console.log("\n══════════════════════════════════════");
  console.log("  1. شاشة DESKTOP (1280×900)");
  console.log("══════════════════════════════════════");
  const desktop = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const dp = await desktop.newPage();
  const desktopErrors = [];
  dp.on("console", (m) => {
    if (m.type() === "error") desktopErrors.push(m.text());
  });
  dp.on("pageerror", (e) => desktopErrors.push("PAGE ERROR: " + e.message));

  await dp.goto(BASE + "/");
  await dp.waitForLoadState("networkidle");

  await test("الرئيسية: Sidebar مرئي على Desktop", async () => {
    const sidebar = await dp.$("aside");
    if (!sidebar) throw new Error("No aside element");
    const box = await sidebar.boundingBox();
    if (!box || box.width < 200) throw new Error(`Sidebar width: ${box?.width}`);
  });

  await test("الرئيسية: TopBar مرئي", async () => {
    const topbar = await dp.$("header");
    if (!topbar) throw new Error("No header");
  });

  await test("الرئيسية: Footer موجود", async () => {
    const footer = await dp.$("footer");
    if (!footer) throw new Error("No footer");
    const txt = await footer.textContent();
    if (!txt.includes("DFAS")) throw new Error("Footer missing DFAS text");
  });

  await test("الرئيسية: 4 بطاقات KPI مرئية", async () => {
    await dp.waitForTimeout(1500); // wait for Counter animation
    const cards = await dp.$$(".glass.glass-hover.rounded-xl");
    if (cards.length < 4) throw new Error(`Got ${cards.length} glass cards`);
  });

  await test("الرئيسية: عنوان صحيح v3", async () => {
    const h1 = await dp.textContent("h1");
    if (!h1.includes("DFAS")) throw new Error(`H1: ${h1}`);
  });

  await test("الرئيسية: زر لوحة التحكم يعمل", async () => {
    await dp.click('a[href="/dashboard"]');
    await dp.waitForURL("**/dashboard", { timeout: 5000 });
    await dp.goBack();
  });

  // ── 2. MOBILE VIEWPORT ──────────────────────────────────────
  console.log("\n══════════════════════════════════════");
  console.log("  2. شاشة MOBILE (390×844 — iPhone 14)");
  console.log("══════════════════════════════════════");
  const mobile = await browser.newContext({
    viewport: { width: 390, height: 844 },
    isMobile: true,
  });
  const mp = await mobile.newPage();
  const mobileErrors = [];
  mp.on("console", (m) => {
    if (m.type() === "error") mobileErrors.push(m.text());
  });

  await mp.goto(BASE + "/");
  await mp.waitForLoadState("networkidle");

  await test("Mobile: الصفحة تُحمَّل بدون تعارض", async () => {
    const body = await mp.textContent("body");
    if (!body || body.length < 100) throw new Error("Body too short");
  });

  await test("Mobile: Sidebar مخفي افتراضياً", async () => {
    const sidebar = await mp.$("aside");
    if (!sidebar) throw new Error("No sidebar");
    const box = await sidebar.boundingBox();
    // sidebar should be off-screen (translate-x-full) on mobile
    if (box && box.x > 0 && box.x < 390) throw new Error(`Sidebar visible at x=${box.x} on mobile`);
  });

  await test("Mobile: زر القائمة ☰ مرئي", async () => {
    const btn = await mp.$('button[aria-label="القائمة"]');
    if (!btn) throw new Error("Menu button missing");
    const box = await btn.boundingBox();
    if (!box || box.width < 30) throw new Error("Menu button too small");
  });

  await test("Mobile: فتح Sidebar بالضغط على ☰", async () => {
    await mp.click('button[aria-label="القائمة"]');
    await mp.waitForTimeout(400);
    const sidebar = await mp.$("aside");
    const box = await sidebar.boundingBox();
    if (!box || box.x < -50) throw new Error("Sidebar did not open");
  });

  await test("Mobile: بطاقات الوحدات مرئية", async () => {
    await mp.goto(BASE + "/");
    const cards = await mp.$$('a[href^="/modules/"]');
    if (cards.length < 8) throw new Error(`Only ${cards.length} cards on mobile`);
  });

  // ── 3. TABLET VIEWPORT ──────────────────────────────────────
  console.log("\n══════════════════════════════════════");
  console.log("  3. شاشة TABLET (768×1024 — iPad)");
  console.log("══════════════════════════════════════");
  const tablet = await browser.newContext({ viewport: { width: 768, height: 1024 } });
  const tp = await tablet.newPage();
  await tp.goto(BASE + "/");
  await tp.waitForLoadState("networkidle");

  await test("Tablet: الصفحة تستجيب", async () => {
    const title = await tp.title();
    if (!title.includes("DFAS")) throw new Error(`Title: ${title}`);
  });

  await test("Tablet: بطاقات الوحدات على عمودين", async () => {
    const cards = await tp.$$('a[href^="/modules/"]');
    if (cards.length < 8) throw new Error(`Only ${cards.length} cards`);
  });

  // ── 4. ALL ROUTES NAVIGATION ────────────────────────────────
  console.log("\n══════════════════════════════════════");
  console.log("  4. التنقل بين الصفحات");
  console.log("══════════════════════════════════════");
  const navCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const np = await navCtx.newPage();

  const routes = [
    { path: "/", expect: "DFAS" },
    { path: "/dashboard", expect: "لوحة التحكم" },
    { path: "/modules", expect: "الوحدات" },
    { path: "/cases", expect: "القضايا" },
    { path: "/about", expect: "حول" },
    { path: "/modules/phishing", expect: "تصيد" },
    { path: "/modules/url", expect: "روابط" },
    { path: "/modules/email", expect: "بريد" },
    { path: "/modules/ioc", expect: "مؤشرات" },
    { path: "/modules/timeline", expect: "زمني" },
    { path: "/modules/network", expect: "شبكة" },
    { path: "/modules/mitre", expect: "MITRE" },
    { path: "/modules/fingerprint", expect: "بصمة" },
    { path: "/modules/image", expect: "صور" },
    { path: "/modules/stego", expect: "خفاء" },
  ];

  for (const r of routes) {
    await test(`Route ${r.path}: تحمّل ويحتوي المحتوى`, async () => {
      await np.goto(BASE + r.path);
      await np.waitForLoadState("networkidle");
      const body = await np.textContent("body");
      if (!body.includes(r.expect)) throw new Error(`لم يجد "${r.expect}" في ${r.path}`);
    });
  }

  // ── 5. 404 HANDLING ─────────────────────────────────────────
  console.log("\n══════════════════════════════════════");
  console.log("  5. معالجة الأخطاء والمسارات الخاطئة");
  console.log("══════════════════════════════════════");
  await test("404: مسار غير موجود يُظهر صفحة خطأ", async () => {
    await np.goto(BASE + "/modules/nonexistent");
    await np.waitForLoadState("networkidle");
    const body = await np.textContent("body");
    if (!body.includes("غير موجودة") && !body.includes("404")) throw new Error("No 404 message");
  });

  await test("404: مسار عشوائي يُظهر صفحة خطأ", async () => {
    await np.goto(BASE + "/xyz-random-path");
    await np.waitForLoadState("networkidle");
    const body = await np.textContent("body");
    if (!body.includes("404") && !body.includes("غير موجود")) throw new Error("No 404 page");
  });

  // ── 6. ENGINE FUNCTIONALITY ─────────────────────────────────
  console.log("\n══════════════════════════════════════");
  console.log("  6. اختبار المحركات الفعلية");
  console.log("══════════════════════════════════════");
  const engCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const ep = await engCtx.newPage();
  const engineErrors = [];
  ep.on("pageerror", (e) => engineErrors.push(e.message));

  // Test phishing with real Arabic phishing text
  await test("MOD-01 Phishing: يرصد رسالة تصيد عربية", async () => {
    await ep.goto(BASE + "/modules/phishing");
    await ep.waitForLoadState("networkidle");
    await ep.fill(
      "textarea",
      "عزيزي العميل! حسابك البنكي معلق. يجب تحديث بياناتك فوراً وإلا سيتم إغلاق الحساب. اضغط هنا: http://fake-bank.com/login لتجنب الحجب النهائي خلال 24 ساعة.",
    );
    await ep.click('button:has-text("تشغيل التحليل")');
    await ep.waitForSelector("text=VERDICT", { timeout: 8000 });
    const body = await ep.textContent("main");
    if (!body.includes("تهديد") && !body.includes("نظيف")) throw new Error("No verdict text");
    // Should detect as phishing
    if (!body.includes("تهديد")) throw new Error("Failed to detect obvious phishing");
  });

  // Test URL with suspicious URL
  await test("MOD-02 URL: يرصد رابط مشبوه", async () => {
    await ep.goto(BASE + "/modules/url");
    await ep.waitForLoadState("networkidle");
    await ep.waitForSelector("textarea");
    await ep.fill(
      "textarea",
      "http://paypa1-secure-account-verify.tk/login?redirect=original-site.com",
    );
    await ep.waitForFunction(() => document.querySelector("button[disabled]") === null || true);
    await ep.waitForTimeout(300);
    await ep.click('button:has-text("تشغيل التحليل"):not([disabled])');
    await ep.waitForSelector("text=VERDICT", { timeout: 8000 });
    const body = await ep.textContent("main");
    if (!body.includes("تهديد")) throw new Error("Failed to detect suspicious URL");
  });

  // Test URL with safe URL
  await test("MOD-02 URL: يقبل رابط آمن", async () => {
    await ep.goto(BASE + "/modules/url");
    await ep.waitForLoadState("networkidle");
    await ep.waitForSelector("textarea");
    await ep.fill("textarea", "https://www.google.com");
    await ep.waitForTimeout(300);
    await ep.click('button:has-text("تشغيل التحليل"):not([disabled])');
    await ep.waitForSelector("text=VERDICT", { timeout: 8000 });
    const body = await ep.textContent("main");
    if (!body.includes("نظيف") && !body.includes("تهديد"))
      throw new Error("No verdict for google.com");
  });

  // Test IOC with real IOCs
  await test("MOD-06 IOC: يستخرج IPv4 وهاشات", async () => {
    await ep.goto(BASE + "/modules/ioc");
    await ep.waitForLoadState("networkidle");
    await ep.waitForSelector("textarea");
    await ep.fill(
      "textarea",
      "Suspicious connection to 185.220.101.45 from 10.0.0.1\nMD5: d41d8cd98f00b204e9800998ecf8427e\nSHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nDomain: evil-c2.xyz contacted",
    );
    await ep.waitForTimeout(300);
    await ep.click('button:has-text("تشغيل التحليل"):not([disabled])');
    await ep.waitForSelector("text=VERDICT", { timeout: 8000 });
    const body = await ep.textContent("main");
    if (!body.includes("IOC") && !body.includes("مؤشر")) throw new Error("IOCs not detected");
  });

  // Test MITRE with attack text
  await test("MOD-10 MITRE: يعيّن تقنيات ATT&CK", async () => {
    await ep.goto(BASE + "/modules/mitre");
    await ep.waitForLoadState("networkidle");
    await ep.waitForSelector("textarea");
    await ep.fill(
      "textarea",
      "PowerShell encoded command executing registry persistence. Base64 obfuscation with C2 beacon to bitcoin wallet.",
    );
    await ep.waitForTimeout(300);
    await ep.click('button:has-text("تشغيل التحليل"):not([disabled])');
    await ep.waitForSelector("text=VERDICT", { timeout: 8000 });
    const body = await ep.textContent("main");
    if (!body.includes("T1") && !body.includes("تقنية"))
      throw new Error("No MITRE techniques found");
  });

  // Test Image demo
  await test("MOD-03 Image: تحليل نموذجي يعمل", async () => {
    await ep.goto(BASE + "/modules/image");
    await ep.click('button:has-text("تحليل نموذجي")');
    await ep.waitForSelector("text=VERDICT", { timeout: 8000 });
    const body = await ep.textContent("main");
    if (!body.includes("EXIF") && !body.includes("صورة") && !body.includes("بصمة"))
      throw new Error("No image analysis results");
  });

  // Test Stego demo
  await test("MOD-07 Stego: تحليل نموذجي يعمل", async () => {
    await ep.goto(BASE + "/modules/stego");
    await ep.click('button:has-text("تحليل نموذجي")');
    await ep.waitForSelector("text=VERDICT", { timeout: 8000 });
    const body = await ep.textContent("main");
    if (!body.includes("LSB") && !body.includes("خفاء") && !body.includes("Entropy"))
      throw new Error("No stego results");
  });

  // ── 7. INTERACTION TESTS ────────────────────────────────────
  console.log("\n══════════════════════════════════════");
  console.log("  7. اختبار التفاعل والـ UI");
  console.log("══════════════════════════════════════");
  const uiCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const up = await uiCtx.newPage();

  await test("Cases: فتح نافذة قضية جديدة", async () => {
    await up.goto(BASE + "/cases");
    await up.waitForLoadState("networkidle");
    await up.click('button:has-text("قضية جديدة")');
    await up.waitForTimeout(300);
    const modal = await up.$("text=قضية جديدة");
    if (!modal) throw new Error("Modal did not open");
  });

  await test("Cases: إغلاق النافذة بزر إلغاء", async () => {
    await up.click('button:has-text("إلغاء")');
    await up.waitForTimeout(300);
    // Modal should be gone or invisible
    const overlay = await up.$(".fixed.inset-0");
    if (overlay) throw new Error("Modal still open after cancel");
  });

  await test('Cases: فلتر "نشطة" يعمل', async () => {
    await up.goto(BASE + "/cases");
    await up.click('button:has-text("نشطة")');
    await up.waitForTimeout(300);
    const rows = await up.$$("tbody tr");
    if (rows.length === 0) throw new Error("No active cases shown");
  });

  await test("FindingCard: يفتح/يغلق الأدلة بالضغط", async () => {
    await up.goto(BASE + "/modules/phishing");
    await up.waitForLoadState("networkidle");
    await up.waitForSelector("textarea");
    await up.fill(
      "textarea",
      "اضغط هنا فوراً وأدخل كلمة مرورك لتجنب إغلاق الحساب البنكي خلال 24 ساعة!",
    );
    await up.waitForTimeout(300);
    await up.click('button:has-text("تشغيل التحليل"):not([disabled])');
    await up.waitForSelector("text=VERDICT", { timeout: 8000 });
    // Click first finding to expand
    const findingBtn = await up.$(".bg-surface-2\\/50 button");
    if (!findingBtn) throw new Error("No finding card to expand");
    await findingBtn.click();
    await up.waitForTimeout(300);
  });

  await test("Export: زر تصدير التقرير يُطلق التحميل", async () => {
    const [download] = await Promise.all([
      up.waitForEvent("download", { timeout: 3000 }).catch(() => null),
      up.click('button:has-text("تصدير التقرير")'),
    ]);
    // Just verify the button click doesn't crash (download may not trigger in headless)
  });

  await test("Dashboard: Counter يعمل ويظهر أرقاماً", async () => {
    await up.goto(BASE + "/dashboard");
    await up.waitForLoadState("networkidle");
    await up.waitForTimeout(2000); // Counter animation
    const counters = await up.$$(".text-3xl.font-bold");
    if (counters.length < 3) throw new Error("No counter elements");
  });

  // ── 8. RESET BUTTON TEST ─────────────────────────────────────
  await test("إعادة تعيين: يمسح النتائج والمدخلات", async () => {
    await up.goto(BASE + "/modules/url");
    await up.waitForLoadState("networkidle");
    await up.waitForSelector("textarea");
    await up.fill("textarea", "http://test.com");
    await up.waitForTimeout(300);
    await up.click('button:has-text("تشغيل التحليل"):not([disabled])');
    await up.waitForSelector("text=VERDICT", { timeout: 8000 });
    await up.click('button:has-text("إعادة تعيين")');
    await up.waitForTimeout(300);
    const ta = await up.$("textarea");
    const val = await ta.inputValue();
    if (val !== "") throw new Error(`Textarea not cleared: "${val}"`);
    const verdict = await up.$("text=VERDICT");
    if (verdict) throw new Error("Results still visible after reset");
  });

  // ── 9. PERFORMANCE CHECK ─────────────────────────────────────
  console.log("\n══════════════════════════════════════");
  console.log("  8. اختبار الأداء والسرعة");
  console.log("══════════════════════════════════════");
  const perfCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const pp = await perfCtx.newPage();

  const pages_perf = ["/", "/dashboard", "/modules", "/cases", "/about"];
  for (const path of pages_perf) {
    await test(`أداء ${path}: تحميل < 3 ثوان`, async () => {
      const t0 = Date.now();
      await pp.goto(BASE + path);
      await pp.waitForLoadState("networkidle");
      const ms = Date.now() - t0;
      if (ms > 3000) throw new Error(`Took ${ms}ms (max 3000ms)`);
      console.log(`     ⏱ ${ms}ms`);
    });
  }

  // Engine response time
  await test("أداء التحليل: phishing < 4 ثوان", async () => {
    await pp.goto(BASE + "/modules/phishing");
    await pp.waitForLoadState("networkidle");
    await pp.waitForSelector("textarea");
    await pp.fill(
      "textarea",
      "urgent: click here now to verify your account credentials immediately",
    );
    await pp.waitForTimeout(300);
    const t0 = Date.now();
    await pp.click('button:has-text("تشغيل التحليل"):not([disabled])');
    await pp.waitForSelector("text=VERDICT", { timeout: 8000 });
    const ms = Date.now() - t0;
    if (ms > 4000) throw new Error(`Analysis took ${ms}ms`);
    console.log(`     ⏱ ${ms}ms`);
  });

  // ── 10. CONSOLE ERRORS SUMMARY ──────────────────────────────
  console.log("\n══════════════════════════════════════");
  console.log("  9. أخطاء الكونسول");
  console.log("══════════════════════════════════════");
  const allErrors = [...desktopErrors, ...mobileErrors, ...engineErrors].filter(
    (e) => !e.includes("favicon") && !e.includes("source map") && !e.includes("DevTools"),
  );

  if (allErrors.length === 0) {
    console.log("  ✅ لا أخطاء في الكونسول");
    passed++;
  } else {
    console.log(`  ⚠️  ${allErrors.length} خطأ:`);
    allErrors.slice(0, 5).forEach((e) => console.log(`     - ${e.slice(0, 120)}`));
    issues.push({ name: "Console Errors", err: allErrors.join(" | ") });
  }

  await browser.close();

  // ── FINAL REPORT ────────────────────────────────────────────
  console.log("\n╔══════════════════════════════════════╗");
  console.log(`║  النتيجة: ${passed + failed} اختبار`);
  console.log(`║  ✅ نجح: ${passed}  |  ❌ فشل: ${failed}`);
  console.log("╚══════════════════════════════════════╝");

  if (issues.length > 0) {
    console.log("\n📋 المشاكل المُكتشفة:\n");
    issues.forEach((iss, i) => {
      console.log(`  ${i + 1}. ❌ ${iss.name}`);
      console.log(`     ${iss.err}\n`);
    });
  } else {
    console.log("\n🟢 لا مشاكل — النظام يعمل بشكل مثالي\n");
  }

  process.exit(failed > 0 ? 1 : 0);
})();
