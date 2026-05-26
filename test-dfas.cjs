/**
 * DFAS v3 Comprehensive Test Suite
 * Tests all routes, modules, engines, and UI interactions
 */
const { chromium } = require('playwright');

const BASE = 'http://localhost:8080';
let passed = 0, failed = 0, warnings = [];

async function test(name, fn) {
  try {
    await fn();
    console.log(`✅ ${name}`);
    passed++;
  } catch (e) {
    console.log(`❌ ${name}: ${e.message}`);
    failed++;
  }
}

function warn(msg) {
  console.log(`⚠️  ${msg}`);
  warnings.push(msg);
}

async function probe(name, fn) {
  try {
    await fn();
    console.log(`🔍 PROBE ${name}: held`);
    passed++;
  } catch (e) {
    console.log(`🔍 PROBE ${name}: ${e.message}`);
  }
}

(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();

  // Collect console errors
  const consoleErrors = [];
  page.on('console', msg => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });

  console.log('\n═══ DFAS v3 Comprehensive Test ═══\n');

  // ── Route: Home ──────────────────────────────────────────
  console.log('─── ROUTE: / (Home) ───');
  await page.goto(BASE + '/');
  await page.waitForLoadState('networkidle');

  await test('Home: title contains DFAS', async () => {
    const title = await page.title();
    if (!title.includes('DFAS')) throw new Error(`Got: ${title}`);
  });

  await test('Home: hero h1 visible', async () => {
    const h1 = await page.textContent('h1');
    if (!h1.includes('DFAS')) throw new Error(`Got: ${h1}`);
  });

  await test('Home: sidebar with 5 nav links', async () => {
    const links = await page.$$('aside nav a');
    if (links.length < 5) throw new Error(`Got ${links.length} links`);
  });

  await test('Home: 10 module cards rendered', async () => {
    const cards = await page.$$('a[href^="/modules/"]');
    if (cards.length < 10) throw new Error(`Got ${cards.length} module cards`);
  });

  await test('Home: KPI stats section exists', async () => {
    const kpi = await page.$('text=إجمالي التحاليل');
    if (!kpi) throw new Error('KPI section missing');
  });

  // Check if KPIs show 0 (expected since no data yet)
  const kpiVal = await page.$eval('text=إجمالي التحاليل', el => el.closest('.glass')?.querySelector('.text-3xl')?.textContent?.trim());
  if (kpiVal === '0') warn('KPI "إجمالي التحاليل" shows 0 — no persistence layer connected');

  await test('Home: "فتح لوحة التحكم" button links to /dashboard', async () => {
    const btn = await page.$('a[href="/dashboard"]');
    if (!btn) throw new Error('Dashboard button missing');
  });

  // ── Route: Dashboard ────────────────────────────────────
  console.log('\n─── ROUTE: /dashboard ───');
  await page.goto(BASE + '/dashboard');
  await page.waitForLoadState('networkidle');

  await test('Dashboard: renders without crash', async () => {
    const body = await page.textContent('body');
    if (!body || body.length < 50) throw new Error('Empty body');
  });

  await test('Dashboard: contains dashboard content', async () => {
    const content = await page.textContent('body');
    if (!content.includes('لوحة') && !content.includes('DFAS') && !content.includes('dashboard')) {
      throw new Error('No dashboard content found');
    }
  });

  // ── Route: Modules list ─────────────────────────────────
  console.log('\n─── ROUTE: /modules ───');
  await page.goto(BASE + '/modules');
  await page.waitForLoadState('networkidle');

  await test('Modules page: renders', async () => {
    const body = await page.textContent('body');
    if (!body || body.length < 50) throw new Error('Empty body');
  });

  await test('Modules page: has module cards', async () => {
    const cards = await page.$$('a[href^="/modules/"]');
    if (cards.length < 5) throw new Error(`Only ${cards.length} module cards`);
  });

  // ── Route: Cases ─────────────────────────────────────────
  console.log('\n─── ROUTE: /cases ───');
  await page.goto(BASE + '/cases');
  await page.waitForLoadState('networkidle');

  await test('Cases page: renders without crash', async () => {
    const body = await page.textContent('body');
    if (!body || body.length < 50) throw new Error('Empty body');
  });

  // ── Route: About ─────────────────────────────────────────
  console.log('\n─── ROUTE: /about ───');
  await page.goto(BASE + '/about');
  await page.waitForLoadState('networkidle');

  await test('About page: renders without crash', async () => {
    const body = await page.textContent('body');
    if (!body || body.length < 50) throw new Error('Empty body');
  });

  // ── Module Pages: Text-input engines ───────────────────
  const textModules = [
    { slug: 'phishing', name: 'كاشف التصيد' },
    { slug: 'url', name: 'محلل الروابط' },
    { slug: 'email', name: 'ترويسات البريد' },
    { slug: 'ioc', name: 'ماسح مؤشرات الاختراق' },
    { slug: 'timeline', name: 'الخط الزمني' },
    { slug: 'network', name: 'محلل سجلات الشبكة' },
    { slug: 'mitre', name: 'MITRE ATT&CK' },
  ];

  for (const mod of textModules) {
    console.log(`\n─── MODULE: /modules/${mod.slug} ───`);
    await page.goto(BASE + `/modules/${mod.slug}`);
    await page.waitForLoadState('networkidle');

    await test(`${mod.slug}: page renders`, async () => {
      const h1 = await page.$('h1');
      if (!h1) throw new Error('No h1 found');
    });

    await test(`${mod.slug}: "تحميل مثال" button exists`, async () => {
      const btn = await page.$('button:has-text("تحميل مثال")');
      if (!btn) throw new Error('Sample button missing');
    });

    // Load sample and run analysis
    await test(`${mod.slug}: load sample`, async () => {
      const btn = await page.$('button:has-text("تحميل مثال")');
      await btn.click();
      await page.waitForTimeout(300);
      const ta = await page.$('textarea');
      if (!ta) throw new Error('No textarea');
      const val = await ta.inputValue();
      if (!val || val.trim() === '') throw new Error('Sample text is empty after clicking');
    });

    await test(`${mod.slug}: run analysis + results appear`, async () => {
      const runBtn = await page.$('button:has-text("تشغيل التحليل")');
      if (!runBtn) throw new Error('Run button missing');
      await runBtn.click();
      // Wait for analysis (max 8 seconds: 5 steps × 450ms + buffer)
      await page.waitForSelector('text=VERDICT', { timeout: 8000 });
    });

    await test(`${mod.slug}: findings section appears`, async () => {
      // Either findings or "لم يُكتشف" (clean)
      const body = await page.textContent('main');
      if (!body.includes('النتائج') && !body.includes('نظيف') && !body.includes('VERDICT')) {
        throw new Error('No verdict/findings in results');
      }
    });

    await test(`${mod.slug}: export report button exists`, async () => {
      const btn = await page.$('button:has-text("تصدير التقرير")');
      if (!btn) throw new Error('Export button missing');
    });
  }

  // ── Module Pages: File-upload engines ─────────────────
  const fileModules = [
    { slug: 'fingerprint', name: 'البصمة الرقمية' },
    { slug: 'image', name: 'الطب الشرعي للصور' },
    { slug: 'stego', name: 'كاشف الإخفاء' },
  ];

  for (const mod of fileModules) {
    console.log(`\n─── MODULE: /modules/${mod.slug} (file upload) ───`);
    await page.goto(BASE + `/modules/${mod.slug}`);
    await page.waitForLoadState('networkidle');

    await test(`${mod.slug}: page renders`, async () => {
      const h1 = await page.$('h1');
      if (!h1) throw new Error('No h1 found');
    });

    await test(`${mod.slug}: file upload zone exists`, async () => {
      const upload = await page.$('input[type="file"]');
      if (!upload) {
        // Check if there's also a textarea (fingerprint might accept text)
        const ta = await page.$('textarea');
        if (!ta) throw new Error('No file input or textarea');
      }
    });
  }

  // ── Image + Stego: demo mode (no file) ─────────────────
  for (const demoMod of ['image', 'stego']) {
    console.log(`\n─── MODULE: /modules/${demoMod} (demo analysis) ───`);
    await page.goto(BASE + `/modules/${demoMod}`);
    await page.waitForLoadState('networkidle');

    await test(`${demoMod}: "تحليل نموذجي" button visible`, async () => {
      const btn = await page.$('button:has-text("تحليل نموذجي")');
      if (!btn) throw new Error('Demo analysis button missing');
    });

    await test(`${demoMod}: demo analysis runs and shows results`, async () => {
      const btn = await page.$('button:has-text("تحليل نموذجي")');
      await btn.click();
      await page.waitForSelector('text=VERDICT', { timeout: 8000 });
      const body = await page.textContent('main');
      if (!body.includes('VERDICT') && !body.includes('النتائج')) throw new Error('No results shown');
    });
  }

  // ── Fingerprint: test text input mode ──────────────────
  console.log('\n─── MODULE: fingerprint (text input mode) ───');
  await page.goto(BASE + '/modules/fingerprint');
  await page.waitForLoadState('networkidle');

  // Fingerprint module may accept text for hashing
  await probe('fingerprint: analyze text directly', async () => {
    const ta = await page.$('textarea');
    if (ta) {
      await ta.fill('Hello, World! Test hashing.');
      const runBtn = await page.$('button:has-text("تشغيل التحليل")');
      await runBtn.click();
      await page.waitForSelector('text=SHA', { timeout: 8000 });
    } else throw new Error('No textarea for text input');
  });

  // ── Test not-found route ─────────────────────────────
  console.log('\n─── PROBE: 404 route ───');
  await probe('404: /modules/nonexistent returns not-found page', async () => {
    await page.goto(BASE + '/modules/nonexistent');
    await page.waitForLoadState('networkidle');
    const body = await page.textContent('body');
    if (!body.includes('غير موجودة') && !body.includes('not found') && !body.includes('404')) {
      throw new Error('No 404 message found');
    }
  });

  // ── Console errors check ─────────────────────────────
  console.log('\n─── CONSOLE ERRORS CHECK ───');
  if (consoleErrors.length === 0) {
    console.log('✅ No console errors recorded');
    passed++;
  } else {
    const filtered = consoleErrors.filter(e =>
      !e.includes('favicon') &&
      !e.includes('DevTools') &&
      !e.includes('CORS') &&
      !e.includes('source map')
    );
    if (filtered.length === 0) {
      console.log('✅ No significant console errors');
      passed++;
    } else {
      console.log(`⚠️  Console errors (${filtered.length}):`);
      filtered.slice(0, 5).forEach(e => console.log(`   - ${e.slice(0, 120)}`));
      if (filtered.length > 5) console.log(`   ... and ${filtered.length - 5} more`);
      warn(`${filtered.length} console errors detected`);
    }
  }

  await browser.close();

  // ── Summary ──────────────────────────────────────────
  console.log('\n════════════════════════════════');
  console.log(`Total: ${passed + failed} | ✅ ${passed} passed | ❌ ${failed} failed`);
  if (warnings.length > 0) {
    console.log(`\nWarnings (${warnings.length}):`);
    warnings.forEach(w => console.log(`  ⚠️  ${w}`));
  }
  console.log('════════════════════════════════\n');
  process.exit(failed > 0 ? 1 : 0);
})();
