/**
 * DFAS — UI Controller + Dashboard + Reports
 * الواجهة الرئيسية + لوحة التحكم + التقارير
 */
'use strict';

/* ── Helpers ── */
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* ── Session ── */
const SESSION_ID = 'SID-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2,6).toUpperCase();

/* ── In-memory state (also persisted to IndexedDB) ── */
const STATE = { ops:[], counts:{ph:0,url:0,img:0,em:0,hash:0,ioc:0,stego:0,tl:0,nl:0,atk:0} };

/* ═══════════════════════════════════
   INIT
═══════════════════════════════════ */
window.addEventListener('DOMContentLoaded', async () => {
  // Session ID display
  $('sb-sid').textContent = SESSION_ID;

  // Clock
  updateClock();
  setInterval(updateClock, 1000);

  // Particle background
  DFAS_Charts.initParticles('bg');

  // Interactive motion graphic
  initThreatMotion();

  // Open DB
  try { await DFAS_DB.open(); } catch(e) { console.warn('IndexedDB unavailable:', e); }

  // Load persisted stats
  await refreshDashboard();
  await refreshCases();

  // Animate home counters
  const total = await DFAS_DB.count('analyses').catch(()=>0);
  if ($('hkpi-total')) DFAS_Charts.counter($('hkpi-total'), total);
  if ($('hkpi-ind'))   DFAS_Charts.counter($('hkpi-ind'), 47);

  // Update sidebar badge
  $('nb-dash').textContent = total;
});

function updateClock() {
  const now = new Date();
  $('sb-clock').textContent = now.toLocaleTimeString('ar-SA', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

/* ═══════════════════════════════════
   NAVIGATION
═══════════════════════════════════ */
const PAGE_TITLES = {
  home:'الرئيسية', dashboard:'لوحة التحكم', phishing:'كاشف التصيد',
  url:'محلل الروابط', image:'جنائيات الصور', email:'ترويسات البريد',
  hash:'البصمة الرقمية', cases:'إدارة القضايا', about:'عن المشروع',
  ioc:'كاشف مؤشرات الاختراق', stego:'كاشف الإخفاء الرقمي',
  tl:'الخط الزمني الرقمي', nl:'سجلات الشبكة', atk:'MITRE ATT&CK'
};

function nav(page) {
  // Hide all pages
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.ni').forEach(n => n.classList.remove('active'));

  // Show target
  const target = $('page-'+page);
  if (target) target.classList.add('active');
  const navItem = document.querySelector(`.ni[data-p="${page}"]`);
  if (navItem) navItem.classList.add('active');

  // Update topbar
  const tb = $('tb-title');
  if (tb) tb.textContent = PAGE_TITLES[page] || page;

  // Close mobile sidebar
  closeSb();

  // Page-specific init
  if (page === 'dashboard') refreshDashboard();
  if (page === 'cases')     refreshCases();
}

function openSb()  { $('sb').classList.add('open'); $('overlay').classList.add('on'); }
function closeSb() { $('sb').classList.remove('open'); $('overlay').classList.remove('on'); }

/* ═══════════════════════════════════
   LOADER HELPER
═══════════════════════════════════ */
function showLoader(id, on, steps=[]) {
  const el = $('ld-'+id);
  if (!el) return;
  el.classList.toggle('on', on);
  if (on && steps.length) {
    let i = 0;
    const se = el.querySelector('.ldr-step');
    const t = setInterval(() => {
      if (i >= steps.length || !el.classList.contains('on')) { clearInterval(t); return; }
      if (se) se.textContent = steps[i++];
    }, 500);
  }
}

function showResult(id, html) {
  const el = $(id);
  if (!el) return;
  el.innerHTML = html;
  el.classList.add('on');
  el.scrollIntoView({behavior:'smooth', block:'nearest'});
}

function animGauge(id, pct, cls) {
  setTimeout(() => {
    const e = $(id);
    if (e) { e.style.width = pct+'%'; e.className='gf '+cls; }
  }, 120);
}

/* ═══════════════════════════════════
   FINDING RENDERER
═══════════════════════════════════ */
function renderFi(f) {
  const title = f.rule || f.label || '';
  return `<div class="fi">
    <div class="fi-sv"><span class="sv sv-${f.sev}">${f.sev}</span></div>
    <div class="fi-body">
      <div class="fi-rule">${esc(title)}</div>
      <div class="fi-det">${esc(f.det || '')}</div>
      ${f.ev ? `<span class="fi-ev">${esc(f.ev)}</span>` : ''}
    </div>
  </div>`;
}

function renderGauge(lbl, pct, cls, gid) {
  return `<div class="gw">
    <div class="gh"><span class="gl">${lbl}</span><span class="gv">${pct}/100</span></div>
    <div class="gt"><div class="gf ${cls}" id="${gid}"></div></div>
  </div>`;
}

function renderVerdict(threat, pct, title, desc) {
  const map = {
    crit:{cls:'crit',ico:'🚨'},
    warn:{cls:'warn',ico:'⚠️'},
    safe:{cls:'safe',ico:'✅'}
  };
  const v = map[threat] || map.safe;
  return `<div class="vrd ${v.cls}">
    <div class="vrd-ico">${v.ico}</div>
    <div class="vrd-body">
      <div class="vrd-ttl">${title}</div>
      <div class="vrd-desc">${desc}</div>
    </div>
    <div class="vrd-sc">${pct}%</div>
  </div>`;
}

/* ═══════════════════════════════════
   LOG HELPER
═══════════════════════════════════ */
async function logOp(mod, label, threat) {
  const entry = { mod, label, threat, ts: new Date().toLocaleTimeString('ar') };
  STATE.ops.unshift(entry);
  STATE.counts[mod] = (STATE.counts[mod]||0) + 1;

  // Persist to IndexedDB
  try {
    await DFAS_DB.saveAnalysis({
      type:mod, label:label.slice(0,80), threat,
      score:0, ts:Date.now()
    });
  } catch(e) {}

  // Update home log
  renderHomeLog();

  // Update dashboard badge
  const total = STATE.ops.length;
  $('nb-dash').textContent = total;
  if ($('hkpi-total')) $('hkpi-total').textContent = total;
}

function renderHomeLog() {
  const el = $('home-log');
  if (!el) return;
  if (!STATE.ops.length) {
    el.innerHTML = `<div style="font-size:11px;color:var(--t3);font-family:var(--mono);padding:8px;">لا توجد عمليات — ابدأ بتشغيل أحد محركات التحليل</div>`;
    return;
  }
  el.innerHTML = STATE.ops.slice(0,5).map(o => `
    <div class="le ${o.threat}">
      <span class="le-ico">${o.threat==='crit'?'🚨':o.threat==='warn'?'⚠️':'✅'}</span>
      <span class="le-txt">${esc(o.label)}</span>
      <span class="le-ts">${o.ts}</span>
    </div>`).join('');
}

/* ═══════════════════════════════════
   MOD-01 PHISHING
═══════════════════════════════════ */
async function runPH() {
  const text = $('ph-in').value.trim();
  if (!text) { alert('الرجاء إدخال نص الرسالة'); return; }

  const steps = ['تهيئة المحرك...','فحص الكلمات المفتاحية...','تحليل البنية اللغوية...','تطبيق نماذج الكشف...','احتساب درجة المخاطر...','إنشاء التقرير...'];
  showLoader('ph', true, steps);
  await sleep(2800);
  showLoader('ph', false);

  const r = PhishingEngine.analyze(text);
  await logOp('ph', `تحليل رسالة تصيد — ${r.pct}%`, r.threat);

  const vm = {
    crit:{t:'تهديد حرج — رسالة تصيد احتيالي موثوقة', d:`رُصد ${r.findings.length} مؤشر خطر.`},
    warn:{t:'مشبوه — يُرجَّح أنها رسالة تصيد', d:`رُصد ${r.findings.length} مؤشر.`},
    safe:{t:'احتمالية منخفضة — النص يبدو مشروعاً', d:`رُصد ${r.findings.length} مؤشر منخفض الخطورة.`}
  }[r.threat];
  const gfc = r.threat==='crit'?'gf-c':r.threat==='warn'?'gf-w':'gf-s';

  showResult('r-ph', `
    <div class="card">
      <div class="card-hd"><div class="card-ttl"><div class="card-ico">📊</div>نتائج التحليل</div><span class="card-meta">${new Date().toLocaleString('ar')}</span></div>
      <div class="card-bd">
        ${renderVerdict(r.threat, r.pct, vm.t, vm.d)}
        ${renderGauge('درجة الخطورة الإجمالية', r.pct, gfc, 'gph1')}
        ${renderGauge('ثقة الكشف (Confidence)', Math.min(r.findings.length*15,97), 'gf-c', 'gph2')}
        <div class="fhd">المؤشرات المكتشفة (${r.findings.length})</div>
        ${r.findings.length ? r.findings.map(renderFi).join('') : renderFi({sev:'INFO',rule:'لم تُكتشف مؤشرات خطر',det:'النص يبدو مشروعاً',ev:''})}
        <div style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);padding:12px;margin-top:8px;">
          <div style="font-size:9px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;">تحليل لغوي إضافي</div>
          <table class="mt">
            <tr><td class="mk">عدد الكلمات</td><td class="mv">${r.meta.words}</td></tr>
            <tr><td class="mk">علامات التعجب</td><td class="mv ${r.meta.exclamations>=2?'w':''}">${r.meta.exclamations}</td></tr>
            <tr><td class="mk">روابط مضمّنة</td><td class="mv ${r.meta.urls.length?'w':''}">${r.meta.urls.length}</td></tr>
            <tr><td class="mk">طول النص</td><td class="mv">${$('ph-in').value.length} حرف</td></tr>
            <tr><td class="mk">رموز أجنبية</td><td class="mv">${r.meta.foreignTokens}</td></tr>
          </table>
        </div>
        <div class="chips">
          ${[...new Set(r.findings.map(f => f.sev))].map(s=>{const m={CRITICAL:'ch-r',HIGH:'ch-a',MEDIUM:'ch-b',LOW:'ch-g'};return`<span class="ch ${m[s]||'ch-v'}">${s}</span>`;}).join('')}
        </div>
      </div>
    </div>`);

  animGauge('gph1', r.pct, gfc);
  animGauge('gph2', Math.min(r.findings.length*15, 97), 'gf-c');
}

/* ═══════════════════════════════════
   MOD-02 URL
═══════════════════════════════════ */
async function runURL() {
  const url = $('url-in').value.trim();
  if (!url) { alert('الرجاء إدخال رابط'); return; }

  const steps = ['DNS Lookup...','TLD Reputation...','Brand Similarity...','Path Heuristics...','Shannon Entropy...','Open Redirect Check...','Report...'];
  showLoader('url', true, steps);
  await sleep(2700);
  showLoader('url', false);

  const r = UrlEngine.analyze(url);
  await logOp('url', url.slice(0,50) + (url.length>50?'…':''), r.threat);

  const vm = {
    crit:{t:'رابط خطير — لا تفتحه', d:`رُصد ${r.findings.length} مؤشر. يُرجَّح أنه يقود لتصيد.`},
    warn:{t:'رابط مشبوه — توخَّ الحذر', d:`رُصد ${r.findings.length} مؤشر متوسط.`},
    safe:{t:'الرابط يبدو آمناً', d:'لم تُرصد مؤشرات خطر بارزة.'}
  }[r.threat];
  const gfc = r.threat==='crit'?'gf-c':r.threat==='warn'?'gf-w':'gf-s';

  showResult('r-url', `
    <div class="card">
      <div class="card-hd"><div class="card-ttl"><div class="card-ico">📊</div>نتائج فحص الرابط</div><span class="card-meta">${new Date().toLocaleString('ar')}</span></div>
      <div class="card-bd">
        ${renderVerdict(r.threat, r.pct, vm.t, vm.d)}
        <div style="background:var(--s3);border:1px solid var(--b1);border-radius:var(--r8);padding:9px 12px;margin-bottom:14px;font-family:var(--mono);font-size:10px;color:var(--tm);word-break:break-all;">${esc(url)}</div>
        ${renderGauge('درجة خطورة الرابط', r.pct, gfc, 'gu1')}
        ${renderGauge(`إنتروبيا النطاق (${r.entropy.toFixed(2)} bits)`, Math.min(Math.round(r.entropy*18),100), r.entropy>3.8?'gf-c':'gf-s', 'gu2')}
        <div class="fhd">المؤشرات المكتشفة (${r.findings.length} / 14)</div>
        ${r.findings.length ? r.findings.map(renderFi).join('') : renderFi({sev:'INFO',rule:'لا توجد مؤشرات خطر',det:'الرابط يبدو سليماً',ev:''})}
        <div style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);padding:12px;margin-top:8px;">
          <div style="font-size:9px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;">تفكيك مكونات الرابط</div>
          <table class="mt">
            <tr><td class="mk">البروتوكول</td><td class="mv ${r.parsed.protocol==='http:'?'w':''}">${esc(r.parsed.protocol)}</td></tr>
            <tr><td class="mk">النطاق</td><td class="mv">${esc(r.parsed.host)}</td></tr>
            <tr><td class="mk">المسار</td><td class="mv">${esc(r.parsed.path)}</td></tr>
            <tr><td class="mk">المعاملات</td><td class="mv ${r.parsed.query!=='—'?'w':''}">${esc(r.parsed.query)}</td></tr>
            <tr><td class="mk">إنتروبيا النطاق</td><td class="mv ${r.entropy>3.8?'w':''}">${r.entropy.toFixed(4)} bits/char</td></tr>
            <tr><td class="mk">الطول الإجمالي</td><td class="mv">${url.length} حرف</td></tr>
          </table>
        </div>
      </div>
    </div>`);

  animGauge('gu1', r.pct, gfc);
  animGauge('gu2', Math.min(Math.round(r.entropy*18),100), r.entropy>3.8?'gf-c':'gf-s');
}

/* ═══════════════════════════════════
   MOD-03 IMAGE
═══════════════════════════════════ */
let _imgFile = null;

function dzOver(e)  { e.preventDefault(); $('img-dz').classList.add('over'); }
function dzLeave()  { $('img-dz').classList.remove('over'); }
function dzDrop(e)  { e.preventDefault(); dzLeave(); const f=e.dataTransfer.files[0]; if(f) setImgFile(f); }
function handleImgFile(e) { const f=e.target.files[0]; if(f) setImgFile(f); }

function setImgFile(f) {
  _imgFile = f;
  const p = $('img-pill');
  p.style.display = 'block';
  p.innerHTML = `<span style="color:var(--grn)">✓</span> ${esc(f.name)} · ${(f.size/1024).toFixed(1)} KB · ${f.type}`;
}

async function runIMG() {
  if (!_imgFile) { alert('الرجاء رفع ملف صورة أولاً أو استخدام زر "تحليل نموذجي"'); return; }
  const steps=['EXIF Parser...','XMP Metadata...','ICC Profile...','Hash Verify...','ELA Analysis...','Steganography Scan...','Report...'];
  showLoader('img', true, steps);
  await sleep(3200);
  showLoader('img', false);
  await renderImageResult(_imgFile);
}

async function runIMGSample() {
  showLoader('img', true, ['EXIF Parser...','ELA Analysis...','Metadata Check...','Report...']);
  await sleep(2800);
  showLoader('img', false);
  await renderImageResult(null);
}

async function renderImageResult(file) {
  const r = await ImageEngine.analyze(file);
  await logOp('img', `جنائيات صورة: ${r.name}`, r.threat);

  showResult('r-img', `
    <div class="card">
      <div class="card-hd"><div class="card-ttl"><div class="card-ico">🔬</div>التقرير الجنائي للصورة</div><span class="card-meta">${new Date().toLocaleString('ar')}</span></div>
      <div class="card-bd">
        ${renderVerdict('crit', r.pct, 'دليل قوي على تزوير وتلاعب', `رُصد ${r.indicators.length} مؤشر جنائي: بصمات تحرير، شذوذ ELA، تعارض بيانات وصفية.`)}
        ${renderGauge('احتمالية التزوير', r.pct, 'gf-c', 'gi1')}
        ${renderGauge('ثقة تحليل ELA', 74, 'gf-w', 'gi2')}
        <div class="fhd">المؤشرات الجنائية (${r.indicators.length})</div>
        ${r.indicators.map(renderFi).join('')}
        <div style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);padding:12px;margin-top:8px;">
          <div style="font-size:9px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;">البيانات الوصفية — EXIF / XMP</div>
          <table class="mt">${r.exifTable.map(row=>`<tr><td class="mk">${row.k}</td><td class="mv ${row.flag}">${row.v}</td></tr>`).join('')}</table>
        </div>
        <div class="chips">${r.chips.map((c,i)=>`<span class="ch ${['ch-r','ch-r','ch-a','ch-a','ch-b','ch-v'][i]||'ch-x'}">${c}</span>`).join('')}</div>
      </div>
    </div>`);

  animGauge('gi1', r.pct, 'gf-c');
  animGauge('gi2', 74, 'gf-w');
}

/* ═══════════════════════════════════
   MOD-04 EMAIL HEADERS
═══════════════════════════════════ */
async function runEM() {
  const raw = $('em-in').value.trim();
  if (!raw) { alert('الرجاء إدخال ترويسات البريد'); return; }

  const steps=['Parsing Headers...','SPF Check...','DKIM Verify...','DMARC Policy...','Routing Analysis...','Mismatch Detection...','Report...'];
  showLoader('em', true, steps);
  await sleep(2600);
  showLoader('em', false);

  const r = EmailEngine.analyze(raw);
  await logOp('em', `تحليل ترويسات بريد — ${r.pct}%`, r.threat);

  const vm = {
    crit:{t:'خطر عالٍ — مؤشرات انتحال وتزوير موثوقة', d:`رُصد ${r.findings.length} مؤشر جنائي في ترويسات البريد.`},
    warn:{t:'مشبوه — يُرجَّح وجود تلاعب', d:`رُصد ${r.findings.length} مؤشر متوسط الخطورة.`},
    safe:{t:'الترويسات تبدو سليمة', d:'لم تُرصد مؤشرات خطر بارزة.'}
  }[r.threat];
  const gfc = r.threat==='crit'?'gf-c':r.threat==='warn'?'gf-w':'gf-s';

  const authColor = v => v==='pass'?'pass':v==='fail'?'fail':v==='softfail'?'soft':'none';

  showResult('r-em', `
    <div class="card">
      <div class="card-hd"><div class="card-ttl"><div class="card-ico">📊</div>نتائج تحليل الترويسات</div><span class="card-meta">${new Date().toLocaleString('ar')}</span></div>
      <div class="card-bd">
        ${renderVerdict(r.threat, r.pct, vm.t, vm.d)}

        <!-- Auth Indicators -->
        <div class="auth-g">
          <div class="auth-c"><div class="auth-lbl">SPF</div><div class="auth-val ${authColor(r.auth.spf)}">${r.auth.spf.toUpperCase()}</div></div>
          <div class="auth-c"><div class="auth-lbl">DKIM</div><div class="auth-val ${authColor(r.auth.dkim)}">${r.auth.dkim.toUpperCase()}</div></div>
          <div class="auth-c"><div class="auth-lbl">DMARC</div><div class="auth-val ${authColor(r.auth.dmarc)}">${r.auth.dmarc.toUpperCase()}</div></div>
        </div>

        ${renderGauge('درجة خطورة الترويسات', r.pct, gfc, 'gem1')}

        <div class="fhd">المؤشرات المكتشفة (${r.findings.length})</div>
        ${r.findings.length ? r.findings.map(renderFi).join('') : renderFi({sev:'INFO',rule:'لا توجد مؤشرات خطر',det:'الترويسات تبدو سليمة',ev:''})}

        <!-- Header Details -->
        <div style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);padding:12px;margin-top:8px;">
          <div style="font-size:9px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;">تفاصيل الترويسات</div>
          <table class="mt">
            <tr><td class="mk">From</td><td class="mv">${esc(r.headers.from)}</td></tr>
            <tr><td class="mk">Return-Path</td><td class="mv ${r.headers.returnPath!==r.headers.from&&r.headers.returnPath!=='—'?'w':''}">${esc(r.headers.returnPath)}</td></tr>
            <tr><td class="mk">Reply-To</td><td class="mv ${r.headers.replyTo!=='—'?'w':''}">${esc(r.headers.replyTo)}</td></tr>
            <tr><td class="mk">Subject</td><td class="mv">${esc(r.headers.subject)}</td></tr>
            <tr><td class="mk">Date</td><td class="mv">${esc(r.headers.date)}</td></tr>
            <tr><td class="mk">X-Mailer</td><td class="mv ${r.headers.xMailer!=='—'?'w':''}">${esc(r.headers.xMailer)}</td></tr>
            <tr><td class="mk">X-Spam-Score</td><td class="mv ${r.headers.xSpam!=='—'?'w':''}">${esc(r.headers.xSpam)}</td></tr>
          </table>
        </div>

        <!-- Routing Chain -->
        ${r.hops.length ? `
        <div style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);padding:12px;margin-top:8px;">
          <div style="font-size:9px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;">سلسلة التوجيه (${r.hops.length} نقطة)</div>
          ${r.hops.map(h=>`
            <div class="hop">
              <div class="hop-n">${h.hop}</div>
              <div class="hop-d">
                <div class="hop-from">${esc(h.from)}</div>
                <div class="hop-by">→ by ${esc(h.by)}</div>
                <div class="hop-ts">${esc(h.ts)}</div>
              </div>
            </div>`).join('')}
        </div>` : ''}
      </div>
    </div>`);

  animGauge('gem1', r.pct, gfc);
}

/* ═══════════════════════════════════
   MOD-05 HASH
═══════════════════════════════════ */
async function runHashTxt() {
  const text = $('hash-txt').value.trim();
  if (!text) { alert('الرجاء إدخال نص'); return; }
  showLoader('hash', true);
  await sleep(800);
  showLoader('hash', false);

  const r = await HashEngine.analyzeText(text);
  await logOp('hash', `بصمة نص — ${text.slice(0,30)}...`, 'safe');
  renderHashResult(r, 'نص');
}

async function runHashFile(e) {
  const file = e.target.files[0];
  if (!file) return;
  showLoader('hash', true);
  await sleep(1000);
  showLoader('hash', false);

  const r = await HashEngine.analyzeFile(file);
  r.isFile = true;
  await logOp('hash', `بصمة ملف: ${file.name}`, 'safe');
  renderHashResult(r, file.name);
}

function renderHashResult(r, label) {
  showResult('r-hash', `
    <div class="card">
      <div class="card-hd"><div class="card-ttl"><div class="card-ico">#️⃣</div>البصمة الرقمية — ${esc(label)}</div><span class="card-meta">${new Date().toLocaleString('ar')}</span></div>
      <div class="card-bd">
        <div style="background:var(--grn-d);border:1px solid rgba(16,185,129,.25);border-radius:var(--r8);padding:11px 14px;margin-bottom:14px;display:flex;align-items:center;gap:9px;">
          <span style="font-size:18px">✅</span>
          <div><div style="font-size:12.5px;font-weight:700;color:var(--grn)">البصمة الرقمية احتُسبت بنجاح</div><div style="font-size:11px;color:var(--t2)">يمكن استخدام هذه البصمات للتحقق من سلامة الأدلة الرقمية</div></div>
        </div>

        <div class="hlbl">SHA-256 (موصى به للأدلة الجنائية)</div>
        <div class="hbox">${esc(r.sha256)}</div>

        <div class="hlbl">SHA-1</div>
        <div class="hbox">${esc(r.sha1)}</div>

        <div class="hlbl">MD5 (للمقارنة فقط — ليس للأمان)</div>
        <div class="hbox">${esc(r.md5)}</div>

        <table class="mt" style="margin-top:12px;">
          ${r.isFile ? `<tr><td class="mk">اسم الملف</td><td class="mv">${esc(r.name||label)}</td></tr><tr><td class="mk">الحجم</td><td class="mv">${(r.size/1024).toFixed(2)} KB</td></tr><tr><td class="mk">النوع</td><td class="mv">${esc(r.type)}</td></tr>` : `<tr><td class="mk">طول النص</td><td class="mv">${r.length} حرف</td></tr><tr><td class="mk">البايتات</td><td class="mv">${r.bytes}</td></tr><tr><td class="mk">الإنتروبيا</td><td class="mv">${r.entropy.toFixed(4)} bits/char</td></tr>`}
          <tr><td class="mk">الوقت</td><td class="mv">${new Date().toLocaleString('ar')}</td></tr>
        </table>

        <div class="chips">
          <span class="ch ch-g">SHA-256 ✓</span>
          <span class="ch ch-b">SHA-1 ✓</span>
          <span class="ch ch-v">MD5 ✓</span>
          <span class="ch" style="background:var(--s3);color:var(--t3);border:1px solid var(--b1)">ISO 27037 Compliant</span>
        </div>
      </div>
    </div>`);
}

function cmpHash() {
  const h1 = $('hc1').value.trim().toLowerCase();
  const h2 = $('hc2').value.trim().toLowerCase();
  const out = $('hc-res');
  if (!h1 || !h2) { out.innerHTML = '<div style="font-size:11px;color:var(--t3);">أدخل كلا البصمتين للمقارنة</div>'; return; }

  if (h1 === h2) {
    out.innerHTML = `<div style="background:var(--grn-d);border:1px solid rgba(16,185,129,.25);border-radius:var(--r8);padding:11px 14px;display:flex;align-items:center;gap:9px;"><span style="font-size:18px">✅</span><div style="font-size:13px;font-weight:700;color:var(--grn)">البصمتان متطابقتان — الملف سليم ولم يُعدَّل</div></div>`;
  } else {
    // Count differing chars
    const diff = Math.max(h1.length, h2.length) - [...h1].filter((c,i)=>c===h2[i]).length;
    out.innerHTML = `<div style="background:var(--red-d);border:1px solid rgba(239,68,68,.25);border-radius:var(--r8);padding:11px 14px;display:flex;align-items:center;gap:9px;"><span style="font-size:18px">🚨</span><div><div style="font-size:13px;font-weight:700;color:var(--red)">البصمتان مختلفتان — تحذير من التلاعب!</div><div style="font-size:11px;color:var(--t2);margin-top:3px;">الفرق: ${diff} حرف — الملف تعرض للتعديل أو التزوير</div></div></div>`;
  }
}

/* ═══════════════════════════════════
   CASES MANAGEMENT
═══════════════════════════════════ */
function toggleCaseForm() {
  const f = $('case-form');
  f.style.display = f.style.display === 'none' ? 'block' : 'none';
}

async function createCase() {
  const title = $('c-title').value.trim();
  const type  = $('c-type').value.trim();
  const notes = $('c-notes').value.trim();
  if (!title) { alert('الرجاء إدخال عنوان القضية'); return; }

  try {
    await DFAS_DB.saveCase({ title, type, notes, status:'جارية', ts:Date.now() });
    $('c-title').value = '';
    $('c-type').value  = '';
    $('c-notes').value = '';
    toggleCaseForm();
    await refreshCases();
  } catch(e) {
    alert('خطأ في حفظ القضية: ' + e.message);
  }
}

async function refreshCases() {
  try {
    const cases = await DFAS_DB.getCases();
    const tbody = $('cases-tbody');
    if (!tbody) return;

    if (!cases.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--t4);padding:22px;font-family:var(--mono);font-size:11px;">لا توجد قضايا بعد</td></tr>';
      return;
    }

    tbody.innerHTML = cases.map(c => `
      <tr>
        <td style="font-family:var(--mono);font-size:10px;color:var(--t3);">${esc(c.caseId)}</td>
        <td style="font-weight:600;color:var(--t1);">${esc(c.title)}</td>
        <td style="color:var(--t2);">${esc(c.type||'—')}</td>
        <td><span style="font-size:9.5px;font-family:var(--mono);padding:2px 8px;border-radius:3px;background:rgba(16,185,129,.12);color:var(--grn);border:1px solid rgba(16,185,129,.25);">${esc(c.status||'—')}</span></td>
        <td style="font-size:10.5px;color:var(--t3);">${new Date(c.ts).toLocaleDateString('ar')}</td>
        <td><button class="btn btn-d btn-sm" onclick="deleteCase('${esc(c.caseId)}')">حذف</button></td>
      </tr>`).join('');
  } catch(e) {}
}

async function deleteCase(id) {
  if (!confirm('هل تريد حذف هذه القضية؟')) return;
  try {
    await DFAS_DB.deleteCase(id);
    await refreshCases();
  } catch(e) { console.error('deleteCase error:', e); }
}

/* ═══════════════════════════════════
   DASHBOARD
═══════════════════════════════════ */
async function refreshDashboard() {
  try {
    const stats = await DFAS_DB.getStats();
    const daily = await DFAS_DB.getDailyStats(7);

    // KPIs
    if ($('d-total')) DFAS_Charts.counter($('d-total'), stats.total);
    if ($('d-crit'))  DFAS_Charts.counter($('d-crit'),  stats.crit);
    if ($('d-warn'))  DFAS_Charts.counter($('d-warn'),  stats.warn);
    if ($('d-safe'))  DFAS_Charts.counter($('d-safe'),  stats.safe);

    // Stacked Bar
    const dc = $('chart-daily');
    if (dc) renderStackedBar(dc, daily);

    // Donut
    const dd = $('chart-donut');
    if (dd) renderDonut(dd, stats);

    // Module usage bars
    renderModBars(stats);

    // Ops Log
    renderDashLog();

  } catch(e) {}
}

function renderStackedBar(el, data) {
  if (!data || !data.length) { el.innerHTML = '<div style="font-size:11px;color:var(--t3);text-align:center;padding:20px;">لا توجد بيانات</div>'; return; }
  const max = Math.max(...data.map(d => (d.crit||0)+(d.warn||0)+(d.safe||0)), 1);

  el.style.display = 'flex';
  el.style.alignItems = 'flex-end';
  el.style.gap = '6px';
  el.innerHTML = data.map(d => {
    const total = (d.crit||0)+(d.warn||0)+(d.safe||0);
    const pc = v => ((v/max)*100).toFixed(1);
    return `<div class="bar-col">
      <div class="bar-v">${total||''}</div>
      <div class="bar-w" style="height:120px">
        <div class="bar-stack" style="width:100%">
          <div class="bar-seg" style="height:0%;background:var(--red)" data-h="${pc(d.crit||0)}"></div>
          <div class="bar-seg" style="height:0%;background:var(--amb)" data-h="${pc(d.warn||0)}"></div>
          <div class="bar-seg" style="height:0%;background:var(--grn)" data-h="${pc(d.safe||0)}"></div>
        </div>
      </div>
      <div class="bar-l">${d.label||''}</div>
    </div>`;
  }).join('');

  requestAnimationFrame(() => {
    el.querySelectorAll('.bar-seg').forEach(b => {
      setTimeout(() => { b.style.height = b.dataset.h+'%'; }, 150);
    });
  });
}

function renderDonut(el, stats) {
  const total = stats.total || 0;
  if (!total) {
    el.innerHTML = `<div style="text-align:center;font-size:11px;color:var(--t3);padding:24px;font-family:var(--mono);">لا توجد بيانات</div>`;
    return;
  }
  const segs = [
    { value: stats.crit, color:'#ef4444', label:'حرجة' },
    { value: stats.warn, color:'#f59e0b', label:'متوسطة' },
    { value: stats.safe, color:'#10b981', label:'سليمة' },
  ].filter(s => s.value > 0);

  DFAS_Charts.donut(el, segs, { size:170, stroke:26, label:String(total), sub:'تحليل' });
}

function renderModBars(stats) {
  const el = $('mod-bars');
  if (!el) return;
  const total = stats.total || 1;
  const mods = [
    { k:'ph',    label:'MOD-01 · تصيد',    color:'var(--red)' },
    { k:'url',   label:'MOD-02 · روابط',   color:'var(--amb)' },
    { k:'img',   label:'MOD-03 · صور',     color:'var(--vio)' },
    { k:'em',    label:'MOD-04 · بريد',    color:'var(--grn)' },
    { k:'hash',  label:'MOD-05 · هاش',     color:'var(--cya)' },
    { k:'ioc',   label:'MOD-06 · IOC',     color:'var(--pri)' },
    { k:'stego', label:'MOD-07 · إخفاء',   color:'#8b5cf6' },
    { k:'tl',    label:'MOD-08 · زمني',    color:'var(--amb)' },
    { k:'nl',    label:'MOD-09 · شبكة',    color:'var(--grn)' },
    { k:'atk',   label:'MOD-10 · ATT&CK',  color:'var(--red)' },
  ];
  el.innerHTML = mods.map(m => {
    const cnt = stats.byType?.[m.k] || 0;
    const pct = Math.round((cnt/total)*100);
    return `<div class="mu-row">
      <div class="mu-hd"><span class="mu-n">${m.label}</span><span class="mu-p">${pct}%</span></div>
      <div class="mu-t"><div class="mu-f" style="width:0%;background:${m.color}" data-w="${pct}"></div></div>
    </div>`;
  }).join('');

  requestAnimationFrame(() => {
    el.querySelectorAll('.mu-f').forEach(b => {
      setTimeout(() => { b.style.width = b.dataset.w+'%'; }, 150);
    });
  });
}

function renderDashLog() {
  const el = $('dash-log');
  if (!el) return;
  if (!STATE.ops.length) {
    el.innerHTML = '<div style="font-size:11px;color:var(--t3);padding:8px;font-family:var(--mono);">لا توجد عمليات بعد.</div>';
    return;
  }
  el.innerHTML = STATE.ops.slice(0,10).map(o => `
    <div class="le ${o.threat}">
      <span class="le-ico">${o.threat==='crit'?'🚨':o.threat==='warn'?'⚠️':'✅'}</span>
      <span class="le-txt">${esc(o.label)}</span>
      <span class="le-ts">${o.ts}</span>
    </div>`).join('');
}

/* ═══════════════════════════════════
   REPORT GENERATOR
═══════════════════════════════════ */
async function generateReport() {
  const stats = await DFAS_DB.getStats().catch(()=>({total:0,crit:0,warn:0,safe:0,byType:{}}));
  const ts    = new Date().toLocaleString('ar-SA');
  const out   = $('rep-out');
  out.classList.add('on');

  const reportId = 'RPT-' + Date.now().toString(36).toUpperCase();

  try {
    await DFAS_DB.saveReport({
      reportId, sessionId:SESSION_ID, ts:Date.now(),
      stats, ops:STATE.ops
    });
  } catch(e){}

  out.innerHTML = `
    <div style="border-top:2px solid var(--pri);padding-top:17px;">
      <div class="rep-title">DIGITAL FORENSIC ANALYSIS REPORT</div>
      <div class="rep-sub">Generated: ${ts} · ${SESSION_ID} · ${reportId}</div>

      <div class="rep-sec">
        <div class="rep-sec-ttl">1 · معلومات القضية والجلسة</div>
        <table class="mt">
          <tr><td class="mk">رقم التقرير</td><td class="mv">${reportId}</td></tr>
          <tr><td class="mk">رقم الجلسة</td><td class="mv">${SESSION_ID}</td></tr>
          <tr><td class="mk">التاريخ والوقت</td><td class="mv">${ts}</td></tr>
          <tr><td class="mk">المنصة</td><td class="mv">DFAS v2.0 — Isolated Local Environment</td></tr>
          <tr><td class="mk">معيار الأدلة</td><td class="mv">ISO/IEC 27037:2012 · NIST SP 800-86</td></tr>
          <tr><td class="mk">تصنيف البيانات</td><td class="mv">TLP:AMBER — أكاديمي مقيد</td></tr>
        </table>
      </div>

      <div class="rep-sec">
        <div class="rep-sec-ttl">2 · ملخص التحليلات الإجمالي</div>
        <table class="mt">
          <tr><td class="mk">إجمالي العمليات</td><td class="mv">${stats.total}</td></tr>
          <tr><td class="mk">MOD-01 · رسائل التصيد</td><td class="mv">${stats.byType?.ph||0}</td></tr>
          <tr><td class="mk">MOD-02 · روابط خبيثة</td><td class="mv">${stats.byType?.url||0}</td></tr>
          <tr><td class="mk">MOD-03 · جنائيات صور</td><td class="mv">${stats.byType?.img||0}</td></tr>
          <tr><td class="mk">MOD-04 · ترويسات بريد</td><td class="mv">${stats.byType?.em||0}</td></tr>
          <tr><td class="mk">MOD-05 · بصمات رقمية</td><td class="mv">${stats.byType?.hash||0}</td></tr>
          <tr><td class="mk">MOD-06 · كاشف IOC</td><td class="mv">${stats.byType?.ioc||0}</td></tr>
          <tr><td class="mk">MOD-07 · كشف الإخفاء</td><td class="mv">${stats.byType?.stego||0}</td></tr>
          <tr><td class="mk">MOD-08 · الخط الزمني</td><td class="mv">${stats.byType?.tl||0}</td></tr>
          <tr><td class="mk">MOD-09 · سجلات الشبكة</td><td class="mv">${stats.byType?.nl||0}</td></tr>
          <tr><td class="mk">MOD-10 · MITRE ATT&CK</td><td class="mv">${stats.byType?.atk||0}</td></tr>
        </table>
      </div>

      <div class="rep-sec">
        <div class="rep-sec-ttl">3 · ملخص التهديدات المكتشفة</div>
        <table class="mt">
          <tr><td class="mk">تهديدات حرجة CRITICAL</td><td class="mv c">${stats.crit}</td></tr>
          <tr><td class="mk">تهديدات متوسطة WARNING</td><td class="mv w">${stats.warn}</td></tr>
          <tr><td class="mk">نتائج سليمة SAFE</td><td class="mv ok">${stats.safe}</td></tr>
          <tr><td class="mk">نسبة الكشف الإجمالية</td><td class="mv">${stats.total>0?Math.round(((stats.crit+stats.warn)/stats.total)*100):0}%</td></tr>
        </table>
      </div>

      <div class="rep-sec">
        <div class="rep-sec-ttl">4 · سجل العمليات التفصيلي</div>
        ${STATE.ops.length ? STATE.ops.map((o,i)=>`<div style="font-size:10px;font-family:var(--mono);color:var(--t2);padding:4px 0;border-bottom:1px solid var(--b1);">[${String(i+1).padStart(2,'0')}] ${o.ts} · ${o.threat.toUpperCase()} · ${esc(o.label)}</div>`).join('') : '<p style="font-size:11px;color:var(--t3)">لا توجد عمليات مسجلة في هذه الجلسة</p>'}
      </div>

      <div style="margin-top:15px;padding:11px 13px;background:rgba(239,68,68,.05);border:1px solid rgba(239,68,68,.14);border-radius:var(--r8);font-size:10px;color:var(--t3);line-height:1.7;">
        ⚖ <strong style="color:var(--t2)">إخلاء مسؤولية:</strong> هذا التقرير أُنشئ في بيئة تعليمية معزولة. البيانات افتراضية لأغراض بحثية حصراً. لا يُعدّ دليلاً قانونياً دون مراجعة خبير جنائي رقمي معتمد.
      </div>
    </div>`;
}

/* ═══════════════════════════════════
   EXPORT & CLEAR
═══════════════════════════════════ */
async function exportData() {
  try {
    const json = await DFAS_DB.exportAll();
    const blob = new Blob([json], {type:'application/json'});
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `DFAS-Export-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch(e) { alert('فشل التصدير: ' + e.message); }
}

async function clearAllData() {
  if (!confirm('هل تريد مسح جميع البيانات المخزنة؟ لا يمكن التراجع.')) return;
  try {
    await DFAS_DB.clearAll();
    STATE.ops = [];
    STATE.counts = {ph:0,url:0,img:0,em:0,hash:0,ioc:0,stego:0,tl:0,nl:0,atk:0};
    renderHomeLog();
    refreshDashboard();
    $('nb-dash').textContent = '0';
    if ($('hkpi-total')) $('hkpi-total').textContent = '0';
    if ($('rep-out')) { $('rep-out').innerHTML = ''; $('rep-out').classList.remove('on'); }
  } catch(e) { alert('فشل المسح: ' + e.message); }
}


/* ── Interactive Motion Graphic ── */
function initThreatMotion() {
  const cv = $('threat-motion');
  if (!cv) return;
  const ctx = cv.getContext('2d');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const motionState = $('motion-state');
  const ptr = { x: 0, y: 0, on: false };
  const nodes = Array.from({ length: reduceMotion ? 12 : 24 }, (_, i) => ({
    x: 40 + (i % 8) * 90 + Math.random()*20,
    y: 30 + Math.floor(i / 8) * 70 + Math.random()*25,
    vx: (Math.random() - 0.5) * 0.6,
    vy: (Math.random() - 0.5) * 0.6,
    risk: i % 5 === 0 ? 2 : i % 3 === 0 ? 1 : 0
  }));

  function resize() {
    const r = cv.getBoundingClientRect();
    cv.width = Math.max(320, Math.floor(r.width));
    cv.height = Math.max(180, Math.floor(r.height));
  }
  resize();
  window.addEventListener('resize', resize);

  cv.addEventListener('mousemove', e => {
    const r = cv.getBoundingClientRect();
    ptr.x = e.clientX - r.left;
    ptr.y = e.clientY - r.top;
    ptr.on = true;
  });
  cv.addEventListener('mouseleave', () => { ptr.on = false; });

  const colors = ['#10b981', '#f59e0b', '#ef4444'];
  let rafId = 0;
  function tick() {
    ctx.clearRect(0,0,cv.width,cv.height);
    for (const n of nodes) {
      n.x += n.vx; n.y += n.vy;
      if (n.x < 8 || n.x > cv.width - 8) n.vx *= -1;
      if (n.y < 8 || n.y > cv.height - 8) n.vy *= -1;
    }
    for (let i=0;i<nodes.length;i++) for (let j=i+1;j<nodes.length;j++) {
      const a=nodes[i], b=nodes[j];
      const d = Math.hypot(a.x-b.x, a.y-b.y);
      if (d < 95) {
        ctx.strokeStyle = `rgba(34,211,238,${(1-d/95)*0.25})`;
        ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke();
      }
    }
    if (ptr.on) {
      for (const n of nodes) {
        const d = Math.hypot(ptr.x-n.x, ptr.y-n.y);
        if (d < 110) {
          n.vx += (ptr.x-n.x) * 0.00002;
          n.vy += (ptr.y-n.y) * 0.00002;
        }
      }
    }
    for (const n of nodes) {
      ctx.fillStyle = colors[n.risk];
      ctx.beginPath(); ctx.arc(n.x,n.y,3.6,0,Math.PI*2); ctx.fill();
    }
    rafId = requestAnimationFrame(tick);
  }

  if (reduceMotion) {
    if (motionState) motionState.textContent = 'REDUCED MOTION / STATIC VIEW';
    ctx.clearRect(0,0,cv.width,cv.height);
    for (const n of nodes) {
      ctx.fillStyle = colors[n.risk];
      ctx.beginPath(); ctx.arc(n.x,n.y,3.6,0,Math.PI*2); ctx.fill();
    }
    return;
  }

  if (motionState) motionState.textContent = 'INTERACTIVE / REAL-TIME';

  document.addEventListener('visibilitychange', () => {
    if (document.hidden && rafId) {
      cancelAnimationFrame(rafId);
      if (motionState) motionState.textContent = 'PAUSED (TAB INACTIVE)';
    } else if (!document.hidden) {
      if (motionState) motionState.textContent = 'INTERACTIVE / REAL-TIME';
      tick();
    }
  });

  tick();
}
