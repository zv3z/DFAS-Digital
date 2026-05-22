/**
 * DFAS — Advanced UI Handlers v2.0
 * واجهات MOD-06 → MOD-10
 */
'use strict';

/* ═══════════════════════════════════════════
   MOD-06 — IOC SCANNER UI
═══════════════════════════════════════════ */
async function runIOC() {
  const text = $('ioc-in').value.trim();
  if (!text) { alert('الرجاء إدخال النص للفحص'); return; }

  const steps = ['استخراج عناوين IP...','فحص النطاقات...','تحليل الهاشات...','كشف كود خبيث...','فحص العملات الرقمية...','تحليل Base64...','مطابقة CVE...','إنشاء التقرير...'];
  showLoader('ioc', true, steps);
  await sleep(3200);
  showLoader('ioc', false);

  const r = IOCEngine.analyze(text);
  await logOp('ioc', `IOC Scanner — ${r.stats.total} مؤشر مستخرج`, r.threat);

  const sevColors = { CRITICAL:['rgba(239,68,68,.1)','rgba(239,68,68,.3)','var(--red)'],HIGH:['rgba(245,158,11,.1)','rgba(245,158,11,.3)','var(--amb)'],MEDIUM:['rgba(14,165,233,.08)','rgba(14,165,233,.25)','var(--pri)'],LOW:['rgba(16,185,129,.08)','rgba(16,185,129,.2)','var(--grn)'],INFO:['rgba(139,92,246,.08)','rgba(139,92,246,.2)','var(--vio)'] };
  const catLabel = { network:'🌐 شبكة',hash:'#️⃣ هاش',identity:'👤 هوية',finance:'💰 مالية',obfus:'🔒 تشفير',malcode:'☠️ كود خبيث',artifact:'📁 أثر نظام',vuln:'⚠ ثغرة' };

  const verdictTxt = {
    crit:{ t:'خطر عالٍ — مؤشرات اختراق موثوقة', d:`استُخرج ${r.stats.total} مؤشر من ${r.results.length} فئة` },
    warn:{ t:'مشبوه — يُرجَّح وجود نشاط خبيث', d:`استُخرج ${r.stats.total} مؤشر يستدعي التحقق` },
    safe:{ t:'منخفض الخطورة — مؤشرات إعلامية', d:`استُخرج ${r.stats.total} مؤشر إعلامي` }
  }[r.threat];

  // Category chart data
  const catKeys = Object.keys(r.stats.byCategory);
  const catMax  = Math.max(...Object.values(r.stats.byCategory), 1);

  showResult('r-ioc', `
    <div class="card">
      <div class="card-hd"><div class="card-ttl"><div class="card-ico">🔍</div>تقرير مؤشرات الاختراق (IOC Report)</div><span class="card-meta">${new Date().toLocaleString('ar')}</span></div>
      <div class="card-bd">
        ${renderVerdict(r.threat, r.pct, verdictTxt.t, verdictTxt.d)}

        <!-- Stats row -->
        <div class="srow">
          <div class="scell"><div class="snum" style="color:var(--pri)">${r.stats.total}</div><div class="slbl">إجمالي المؤشرات</div></div>
          <div class="scell"><div class="snum" style="color:var(--red)">${r.stats.bySeverity.CRITICAL||0}</div><div class="slbl">حرجة</div></div>
          <div class="scell"><div class="snum" style="color:var(--amb)">${r.stats.bySeverity.HIGH||0}</div><div class="slbl">عالية</div></div>
          <div class="scell"><div class="snum" style="color:var(--grn)">${r.results.length}</div><div class="slbl">نوع مؤشر</div></div>
        </div>

        ${renderGauge('مستوى الخطورة الإجمالي', r.pct, r.threat==='crit'?'gf-c':r.threat==='warn'?'gf-w':'gf-s', 'gioc1')}

        <!-- Category distribution -->
        <div style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);padding:14px;margin-bottom:14px;">
          <div style="font-size:9px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-bottom:10px;">توزيع المؤشرات حسب الفئة</div>
          ${catKeys.map(cat => {
            const cnt = r.stats.byCategory[cat];
            const pct = Math.round((cnt/catMax)*100);
            return `<div style="margin-bottom:8px;">
              <div style="display:flex;justify-content:space-between;font-size:10px;margin-bottom:3px;">
                <span style="color:var(--t2)">${catLabel[cat]||cat}</span>
                <span style="font-family:var(--mono);color:var(--t1)">${cnt}</span>
              </div>
              <div style="height:4px;background:var(--s3);border-radius:2px;overflow:hidden;">
                <div style="height:100%;border-radius:2px;background:var(--pri);width:0%;transition:width .9s ease" data-w="${pct}" class="ioc-bar"></div>
              </div>
            </div>`;
          }).join('')}
        </div>

        <!-- IOC results by type -->
        <div class="fhd">المؤشرات المستخرجة حسب النوع (${r.results.length} نوع)</div>
        ${r.results.sort((a,b) => {const o={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};return (o[a.sev]||5)-(o[b.sev]||5);}).map(res => {
          const [bg,border,color] = sevColors[res.sev] || sevColors.INFO;
          return `<div class="fi" style="background:${bg};border-color:${border}">
            <div class="fi-sv"><span class="sv sv-${res.sev}">${res.sev}</span></div>
            <div class="fi-body">
              <div class="fi-rule">${catLabel[res.cat]||res.cat} — ${esc(res.label)} <span style="color:var(--t3);font-size:10px;">(${res.count})</span></div>
              <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:5px;">
                ${res.samples.map(s => `<span class="fi-ev" style="color:${color}">${esc(s.value.slice(0,60))}${s.extra?` <span style="color:var(--red)">${esc(s.extra)}</span>`:''}</span>`).join('')}
                ${res.all.length > 5 ? `<span style="font-size:9px;color:var(--t4);padding:2px 6px;">+${res.all.length-5} آخرين</span>` : ''}
              </div>
            </div>
          </div>`;
        }).join('')}
      </div>
    </div>`);

  animGauge('gioc1', r.pct, r.threat==='crit'?'gf-c':r.threat==='warn'?'gf-w':'gf-s');
  setTimeout(() => { document.querySelectorAll('.ioc-bar').forEach(b => { b.style.width = b.dataset.w+'%'; }); }, 200);
}

/* ═══════════════════════════════════════════
   MOD-07 — STEGANOGRAPHY DETECTOR UI
═══════════════════════════════════════════ */
let _stegoFile = null;

function stegoOver(e)  { e.preventDefault(); $('stego-dz').classList.add('over'); }
function stegoLeave()  { $('stego-dz').classList.remove('over'); }
function stegoDrop(e)  { e.preventDefault(); stegoLeave(); const f=e.dataTransfer.files[0]; if(f) setStegoFile(f); }
function handleStegoFile(e) { const f=e.target.files[0]; if(f) setStegoFile(f); }

function setStegoFile(f) {
  _stegoFile = f;
  const p = $('stego-pill');
  p.style.display = 'block';
  p.innerHTML = `<span style="color:var(--grn)">✓</span> ${esc(f.name)} · ${(f.size/1024).toFixed(1)} KB`;
}

async function runStego() {
  const steps = ['تحميل الصورة...','تحليل البتات (LSB)...','اختبار Chi-Square...','تحليل الإنتروبيا...','Pixel Pair Analysis...','فحص حجم الملف...','تجميع النتائج...'];
  showLoader('stego', true, steps);
  await sleep(3500);
  showLoader('stego', false);

  const r = await StegoEngine.analyzeFile(_stegoFile);
  await logOp('stego', `كشف إخفاء: ${_stegoFile?.name||'نموذج'}`, r.threat);
  renderStegoResult(r);
}

async function runStegoSample() {
  showLoader('stego', true, ['Chi-Square...','LSB Analysis...','Entropy...','Report...']);
  await sleep(3000);
  showLoader('stego', false);
  const r = StegoEngine.analyzeSimulated(null);
  await logOp('stego', 'كشف إخفاء رقمي — نموذج', r.threat);
  renderStegoResult(r);
}

function renderStegoResult(r) {
  const lsb = r.stats;
  const gfc = r.threat==='crit'?'gf-c':r.threat==='warn'?'gf-w':'gf-s';
  const vm  = {
    crit:{ t:'كشف إخفاء رقمي — بيانات مخفية بدرجة عالية من الثقة', d:`رُصد ${r.indicators.length} مؤشر إحصائي يُثبت وجود بيانات مُخفاة` },
    warn:{ t:'مشبوه — احتمال وجود إخفاء رقمي', d:`رُصد ${r.indicators.length} مؤشر يستدعي مزيداً من التحقيق` },
    safe:{ t:'لم يُكتشف إخفاء رقمي', d:'التحليل الإحصائي لا يُشير لوجود بيانات مخفية' }
  }[r.threat];

  showResult('r-stego', `
    <div class="card">
      <div class="card-hd"><div class="card-ttl"><div class="card-ico">🔬</div>تقرير تحليل الإخفاء الرقمي</div><span class="card-meta">${new Date().toLocaleString('ar')}</span></div>
      <div class="card-bd">
        ${renderVerdict(r.threat, r.pct, vm.t, vm.d)}
        ${renderGauge('احتمالية الإخفاء الرقمي', r.pct, gfc, 'gst1')}

        <!-- LSB Stats grid -->
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin-bottom:14px;">
          ${[
            {l:'LSB Channel R', v:(lsb.lsbR?.ratio*100||0).toFixed(1)+'%', flag:lsb.lsbR?.suspicious, color:'var(--red)'},
            {l:'LSB Channel G', v:(lsb.lsbG?.ratio*100||0).toFixed(1)+'%', flag:lsb.lsbG?.suspicious, color:'var(--grn)'},
            {l:'LSB Channel B', v:(lsb.lsbB?.ratio*100||0).toFixed(1)+'%', flag:lsb.lsbB?.suspicious, color:'var(--pri)'},
            {l:'RS Pixel Pair', v:(lsb.ppa?.ratio*100||0).toFixed(1)+'%',  flag:lsb.ppa?.suspicious,  color:'var(--amb)'},
          ].map(s => `<div class="scell" style="border-color:${s.flag?'rgba(239,68,68,.3)':'var(--b1)'}">
            <div class="snum" style="font-size:18px;color:${s.flag?'var(--red)':s.color}">${s.v}</div>
            <div class="slbl">${s.l}</div>
            ${s.flag?'<div style="font-size:8px;color:var(--red);margin-top:3px;">⚠ مشبوه</div>':''}
          </div>`).join('')}
        </div>

        <!-- Technical stats -->
        <div style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);padding:12px;margin-bottom:14px;">
          <div style="font-size:9px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;">مؤشرات إحصائية تفصيلية</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <table class="mt">
              <tr><td class="mk">Shannon Entropy</td><td class="mv ${parseFloat(lsb.entropy)>7.8?'w':''}">${lsb.entropy} bits/byte</td></tr>
              <tr><td class="mk">Chi-Square (χ²)</td><td class="mv ${parseFloat(lsb.chi)<260?'w':'ok'}">${lsb.chi}</td></tr>
              <tr><td class="mk">RS Pair Ratio</td><td class="mv ${lsb.ppa?.suspicious?'c':''}">${(lsb.ppa?.ratio*100||0).toFixed(1)}%</td></tr>
            </table>
            <table class="mt">
              <tr><td class="mk">الأبعاد</td><td class="mv">${lsb.width}×${lsb.height} px</td></tr>
              <tr><td class="mk">إجمالي البكسل</td><td class="mv">${(lsb.pixels||0).toLocaleString()}</td></tr>
              <tr><td class="mk">طريقة الكشف</td><td class="mv" style="color:var(--pri)">LSB+RS+χ²</td></tr>
            </table>
          </div>
        </div>

        <div class="fhd">المؤشرات المكتشفة (${r.indicators.length})</div>
        ${r.indicators.map(renderFi).join('')}

        <div class="chips">
          <span class="ch ch-b">LSB Analysis</span>
          <span class="ch ch-v">Chi-Square Test</span>
          <span class="ch ch-a">Entropy Analysis</span>
          <span class="ch ch-r">RS Method</span>
          ${r.threat==='crit'?'<span class="ch ch-r">Steganography Detected</span>':''}
        </div>
      </div>
    </div>`);
  animGauge('gst1', r.pct, gfc);
}

/* ═══════════════════════════════════════════
   MOD-08 — DIGITAL TIMELINE UI
═══════════════════════════════════════════ */
async function runTimeline() {
  const text = $('tl-in').value.trim();
  if (!text) { alert('الرجاء إدخال النص'); return; }

  const steps = ['مسح الطوابع الزمنية...','تحليل ISO 8601...','تحليل Syslog...','تحليل Apache Log...','كشف الفجوات الزمنية...','كشف النشاط خارج الدوام...','رسم الخط الزمني...'];
  showLoader('tl', true, steps);
  await sleep(2600);
  showLoader('tl', false);

  const r = TimelineEngine.analyze(text);
  await logOp('tl', `خط زمني — ${r.total} حدث`, r.total>0?(r.anomalies.length>3?'crit':r.anomalies.length>0?'warn':'safe'):'safe');
  renderTimelineResult(r);
}

function renderTimelineResult(r) {
  if (!r.total) {
    showResult('r-tl', `<div class="card"><div class="card-bd"><div style="text-align:center;padding:20px;color:var(--t3);font-family:var(--mono);">لم يُعثر على طوابع زمنية في النص المدخل</div></div></div>`);
    return;
  }

  const anom = r.anomalies;
  const anomCrit = anom.filter(a => a.type==='burst'||a.type==='future');
  const threat   = anomCrit.length>=2?'crit':anom.length>0?'warn':'safe';

  /* Build SVG timeline */
  const svgH  = Math.min(r.total * 28 + 60, 500);
  const tMin  = r.events[0]?.ts || 0;
  const tMax  = r.events[r.events.length-1]?.ts || tMin + 1;
  const tSpan = tMax - tMin || 1;

  const anomTs = new Set(anom.map(a => a.anchor?.ts || a.events?.[0]?.ts || a.event?.ts));

  const dots = r.events.map((ev, i) => {
    const x    = 30 + ((ev.ts - tMin) / tSpan) * 680;
    const y    = 30 + i * Math.min(28, (svgH-60)/Math.max(r.total,1));
    const isAnom = anomTs.has(ev.ts);
    const color  = isAnom ? '#ef4444' : '#0ea5e9';
    return `<circle cx="${x.toFixed(0)}" cy="${y.toFixed(0)}" r="${isAnom?6:4}" fill="${color}" opacity="${isAnom?1:0.7}">
      <title>${esc(ev.raw)} — ${ev.fmt}</title>
    </circle>
    <line x1="30" y1="${y.toFixed(0)}" x2="${x.toFixed(0)}" y2="${y.toFixed(0)}" stroke="rgba(14,165,233,.12)" stroke-width="1" stroke-dasharray="3,3"/>
    <text x="710" y="${(parseInt(y)+4).toFixed(0)}" font-size="9" fill="#4d6682" font-family="IBM Plex Mono">${esc(ev.date?.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'})||'')}</text>`;
  }).join('');

  const timeline_svg = `<svg viewBox="0 0 740 ${svgH}" width="100%" style="max-height:${svgH}px;overflow:visible">
    <line x1="30" y1="20" x2="30" y2="${svgH-20}" stroke="rgba(14,165,233,.3)" stroke-width="1.5"/>
    ${dots}
    <circle cx="30" cy="20" r="5" fill="var(--grn)"/><circle cx="30" cy="${svgH-20}" r="5" fill="var(--amb)"/>
    <text x="36" y="24" font-size="9" fill="#10b981" font-family="IBM Plex Mono">${esc(r.earliest?.toLocaleDateString('ar-SA')||'')}</text>
    <text x="36" y="${svgH-14}" font-size="9" fill="#f59e0b" font-family="IBM Plex Mono">${esc(r.latest?.toLocaleDateString('ar-SA')||'')}</text>
  </svg>`;

  /* Anomaly descriptions */
  const anomDesc = {
    gap    : a => `فجوة زمنية ${a.gapH} ساعة`,
    burst  : a => `نشاط مكثف — ${a.count} حدث في 5 دقائق`,
    future : a => `طابع زمني مستقبلي: ${new Date(a.event.ts).toLocaleDateString('ar')}`,
    offhours: a => `نشاط خارج الدوام — ${a.hour}:00 ص`
  };

  showResult('r-tl', `
    <div class="card">
      <div class="card-hd"><div class="card-ttl"><div class="card-ico">⏱</div>الخط الزمني الرقمي (${r.total} حدث)</div><span class="card-meta">Span: ${r.span}h</span></div>
      <div class="card-bd">
        ${renderVerdict(threat, Math.min(anom.length*15,99)||5,
          threat==='crit'?'شذوذات زمنية حرجة مكتشفة':threat==='warn'?'مؤشرات زمنية مشبوهة':'الخط الزمني منتظم',
          `${r.total} حدث على مدى ${r.span} ساعة · ${anom.length} شذوذ مكتشف`)}

        <div class="srow">
          <div class="scell"><div class="snum" style="color:var(--pri)">${r.total}</div><div class="slbl">إجمالي الأحداث</div></div>
          <div class="scell"><div class="snum" style="color:var(--red)">${anomCrit.length}</div><div class="slbl">شذوذات حرجة</div></div>
          <div class="scell"><div class="snum" style="color:var(--amb)">${anom.length}</div><div class="slbl">إجمالي الشذوذات</div></div>
          <div class="scell"><div class="snum" style="color:var(--t2)">${r.span}h</div><div class="slbl">امتداد زمني</div></div>
        </div>

        <!-- SVG Timeline visualization -->
        <div style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);padding:14px;margin-bottom:14px;overflow:hidden;">
          <div style="font-size:9px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-bottom:10px;">🗓 تصوير الخط الزمني</div>
          ${timeline_svg}
        </div>

        <!-- Events list -->
        <div class="fhd">سجل الأحداث الزمنية (${Math.min(r.events.length,20)} من ${r.events.length})</div>
        ${r.events.slice(0,20).map((ev,i) => {
          const isAnom = anomTs.has(ev.ts);
          return `<div class="fi" style="${isAnom?'background:rgba(239,68,68,.06);border-color:rgba(239,68,68,.2)':''}">
            <div class="fi-sv"><span class="sv ${isAnom?'sv-HIGH':'sv-INFO'}">${String(i+1).padStart(2,'0')}</span></div>
            <div class="fi-body">
              <div class="fi-rule" style="font-family:var(--mono);font-size:11px;">${esc(ev.raw)}</div>
              <div class="fi-det">${esc(ev.fmt)} · ${ev.date?.toLocaleString('ar')}</div>
              ${ev.context?`<span class="fi-ev">${esc(ev.context)}</span>`:''}
            </div>
          </div>`;
        }).join('')}

        <!-- Anomalies -->
        ${anom.length ? `
        <div class="fhd" style="margin-top:14px;">الشذوذات الزمنية المكتشفة (${anom.length})</div>
        ${anom.map(a => renderFi({sev:a.type==='future'||a.type==='burst'?'CRITICAL':'HIGH', rule:anomDesc[a.type]?.(a)||a.type, det:a.type==='gap'?`فجوة بين ${new Date(a.events[0].ts).toLocaleString('ar')} و${new Date(a.events[1].ts).toLocaleString('ar')}`:`الخط الزمني يُظهر ${a.type}`, ev:''})).join('')}
        ` : ''}
      </div>
    </div>`);
}

/* ═══════════════════════════════════════════
   MOD-09 — NETWORK LOG ANALYZER UI
═══════════════════════════════════════════ */
async function runNetLog() {
  const text = $('nl-in').value.trim();
  if (!text) { alert('الرجاء إدخال سجلات الشبكة'); return; }

  const steps = ['تحليل صيغة السجلات...','استخراج عناوين IP...','كشف Brute Force...','كشف الأدوات الهجومية...','فحص مسارات الاستغلال...','تحليل رموز HTTP...','إنشاء التقرير...'];
  showLoader('nl', true, steps);
  await sleep(3000);
  showLoader('nl', false);

  const r = NetLogEngine.analyze(text);
  await logOp('nl', `سجلات شبكة — ${r.stats.totalReq} طلب`, r.threat);

  const gfc = r.threat==='crit'?'gf-c':r.threat==='warn'?'gf-w':'gf-s';
  const statusTotal = Object.values(r.stats.statusMap).reduce((a,b)=>a+b,0)||1;
  const topIPs = r.stats.topIPs || [];

  showResult('r-nl', `
    <div class="card">
      <div class="card-hd"><div class="card-ttl"><div class="card-ico">🌐</div>تقرير تحليل سجلات الشبكة</div><span class="card-meta">${new Date().toLocaleString('ar')}</span></div>
      <div class="card-bd">
        ${renderVerdict(r.threat, r.pct,
          r.threat==='crit'?'تهديد حرج — هجمات نشطة مكتشفة':r.threat==='warn'?'نشاط مشبوه في السجلات':'السجلات تبدو طبيعية',
          `فُحص ${r.stats.totalReq} طلب · ${r.findings.length} تهديد مكتشف`)}

        <div class="srow">
          <div class="scell"><div class="snum" style="color:var(--pri)">${r.stats.totalReq}</div><div class="slbl">إجمالي الطلبات</div></div>
          <div class="scell"><div class="snum" style="color:var(--red)">${r.stats.exploitPaths||0}</div><div class="slbl">طلبات استغلال</div></div>
          <div class="scell"><div class="snum" style="color:var(--amb)">${r.stats.scannerCount||0}</div><div class="slbl">أدوات هجومية</div></div>
          <div class="scell"><div class="snum" style="color:var(--grn)">${topIPs.length}</div><div class="slbl">عناوين IP</div></div>
        </div>

        ${renderGauge('مستوى خطورة السجلات', r.pct, gfc, 'gnl1')}

        <div class="g2">
          <!-- HTTP Status codes -->
          <div style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);padding:12px;">
            <div style="font-size:9px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-bottom:9px;">توزيع رموز HTTP</div>
            ${[{code:'2xx',label:'نجاح',color:'var(--grn)'},{code:'3xx',label:'توجيه',color:'var(--pri)'},{code:'4xx',label:'خطأ عميل',color:'var(--amb)'},{code:'5xx',label:'خطأ خادم',color:'var(--red)'}].map(s => {
              const k = parseInt(s.code[0]);
              const cnt = r.stats.statusMap[k]||0;
              const pct = Math.round((cnt/statusTotal)*100);
              return `<div style="margin-bottom:7px;">
                <div style="display:flex;justify-content:space-between;font-size:10px;margin-bottom:3px;">
                  <span style="color:var(--t2)">${s.code} · ${s.label}</span>
                  <span style="font-family:var(--mono);color:${s.color}">${cnt} (${pct}%)</span>
                </div>
                <div style="height:4px;background:var(--s3);border-radius:2px;overflow:hidden;">
                  <div style="height:100%;border-radius:2px;background:${s.color};width:0%;transition:width .9s ease" data-w="${pct}" class="nl-bar"></div>
                </div>
              </div>`;
            }).join('')}
          </div>

          <!-- Top IPs -->
          <div style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);padding:12px;">
            <div style="font-size:9px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-bottom:9px;">أكثر عناوين IP نشاطاً</div>
            ${topIPs.slice(0,7).map(([ip,cnt]) => {
              const pct = Math.round((cnt/(topIPs[0]?.[1]||1))*100);
              const isSusp = cnt > 20;
              return `<div style="margin-bottom:6px;display:flex;align-items:center;gap:8px;">
                <span style="font-family:var(--mono);font-size:10px;color:${isSusp?'var(--red)':'var(--t2)'};min-width:110px;">${esc(ip)}</span>
                <div style="flex:1;height:4px;background:var(--s3);border-radius:2px;overflow:hidden;">
                  <div style="height:100%;border-radius:2px;background:${isSusp?'var(--red)':'var(--pri)'};width:${pct}%;"></div>
                </div>
                <span style="font-family:var(--mono);font-size:9px;color:var(--t3)">${cnt}</span>
              </div>`;
            }).join('')}
            ${r.stats.totalBytes ? `<div style="margin-top:8px;font-size:10px;color:var(--t3)">إجمالي البيانات: <span style="color:var(--t1);font-family:var(--mono)">${(r.stats.totalBytes/1024/1024).toFixed(1)} MB</span></div>` : ''}
          </div>
        </div>

        <div class="fhd" style="margin-top:14px;">التهديدات المكتشفة (${r.findings.length})</div>
        ${r.findings.length ? r.findings.map(renderFi).join('') : renderFi({sev:'INFO',rule:'لم تُكتشف تهديدات',det:'السجلات تبدو طبيعية',ev:''})}
      </div>
    </div>`);

  animGauge('gnl1', r.pct, gfc);
  setTimeout(() => { document.querySelectorAll('.nl-bar').forEach(b => { b.style.width = b.dataset.w+'%'; }); }, 200);
}

/* ═══════════════════════════════════════════
   MOD-10 — MITRE ATT&CK MAPPER UI
═══════════════════════════════════════════ */
async function runATTACK() {
  const text = $('atk-in').value.trim();
  if (!text) { alert('الرجاء إدخال نص التحليل أو الأدلة'); return; }

  const steps = ['تحليل المؤشرات...','بحث في قاعدة ATT&CK...','ربط التكتيكات...','احتساب Kill Chain...','رسم مصفوفة ATT&CK...'];
  showLoader('atk', true, steps);
  await sleep(2400);
  showLoader('atk', false);

  const r = ATTACKEngine.analyze(text);
  await logOp('atk', `MITRE ATT&CK — ${r.total} تقنية`, r.total>4?'crit':r.total>1?'warn':'safe');
  renderATTACKResult(r);
}

function renderATTACKResult(r) {
  if (!r.total) {
    showResult('r-atk', `<div class="card"><div class="card-bd"><div style="text-align:center;padding:20px;color:var(--t3);font-family:var(--mono);">لم يُكتشف ربط بتقنيات ATT&CK — حاول إدخال نتائج التحليل من المحركات الأخرى</div></div></div>`);
    return;
  }

  const threat = r.total >= 5 ? 'crit' : r.total >= 2 ? 'warn' : 'safe';
  const pct    = Math.min(r.total * 12, 99);

  /* Kill Chain progress */
  const kcStages = ['Recon','Initial Access','Execution','Persistence','Priv Esc','Defense Evasion','Cred Access','Discovery','Lateral Mov','Collection','Exfiltration','C2','Impact'];
  const kcAr     = ['الاستطلاع','الوصول الأولي','التنفيذ','الثبات','رفع الصلاحيات','التهرب','الاعتمادات','الاكتشاف','الحركة','جمع البيانات','التسريب','التحكم C2','الأثر'];
  const tacticOrder = ['TA0043','TA0001','TA0002','TA0003','TA0004','TA0005','TA0006','TA0007','TA0008','TA0009','TA0010','TA0011','TA0040'];

  /* ATT&CK Matrix SVG */
  const matrixRows = Object.entries(r.byTactic);
  const matSVG = matrixRows.map(([taId, tactic], row) => {
    const tacticInfo = r.TACTICS[taId] || {};
    const techs = tactic.techniques || [];
    const techLabels = techs.map(t => `${t.id}: ${t.name.slice(0,18)}`).join('\n');
    return `<g transform="translate(${row * 115}, 0)">
      <rect width="110" height="40" rx="3" fill="${tacticInfo.color||'#0ea5e9'}33" stroke="${tacticInfo.color||'#0ea5e9'}" stroke-width="1.5"/>
      <text x="55" y="14" text-anchor="middle" font-size="8" font-weight="700" fill="${tacticInfo.color||'#0ea5e9'}" font-family="IBM Plex Mono">${esc(taId)}</text>
      <text x="55" y="25" text-anchor="middle" font-size="7" fill="#8fa6c0" font-family="IBM Plex Sans Arabic">${esc(tacticInfo.ar||tactic.name||'')}</text>
      <text x="55" y="36" text-anchor="middle" font-size="7" fill="#4d6682" font-family="IBM Plex Mono">${techs.length} تقنية</text>
      <title>${techLabels}</title>
    </g>`;
  }).join('');

  const svgW = Math.max(matrixRows.length * 115, 200);

  /* Kill chain stages */
  const kcHTML = tacticOrder.map((ta, i) => {
    const active = r.activeTactics.includes(ta);
    const isMax  = ta === r.activeTactics[r.activeTactics.length-1];
    return `<div style="display:flex;flex-direction:column;align-items:center;gap:4px;">
      <div style="width:34px;height:34px;border-radius:50%;border:2px solid ${active?'var(--pri)':'var(--b2)'};
        background:${isMax?'var(--pri)':active?'var(--pri-d)':'var(--s3)'};
        display:flex;align-items:center;justify-content:center;font-size:9px;font-family:var(--mono);
        color:${active?'var(--t1)':'var(--t4)'};font-weight:700;">${i+1}</div>
      <div style="font-size:8px;color:${active?'var(--t1)':'var(--t4)'};text-align:center;font-family:var(--mono);">${esc(kcStages[i]||'')}</div>
    </div>`;
  }).join(`<div style="flex:1;height:2px;background:${true?'var(--b2)':'var(--b1)'};margin-bottom:22px;margin-top:17px;"></div>`);

  showResult('r-atk', `
    <div class="card">
      <div class="card-hd"><div class="card-ttl"><div class="card-ico">🎯</div>تقرير ربط MITRE ATT&CK</div><span class="card-meta">ATT&CK v14 · ${r.total} تقنية</span></div>
      <div class="card-bd">
        ${renderVerdict(threat, pct,
          `${r.total} تقنية ATT&CK مُرتبطة عبر ${r.tacticCount} تكتيك`,
          `Kill Chain Stage: ${kcStages[r.killChainStage]||'N/A'} — المرحلة ${r.killChainStage+1}/13`)}

        <div class="srow">
          <div class="scell"><div class="snum" style="color:var(--pri)">${r.total}</div><div class="slbl">تقنية مُرتبطة</div></div>
          <div class="scell"><div class="snum" style="color:var(--amb)">${r.tacticCount}</div><div class="slbl">تكتيك</div></div>
          <div class="scell"><div class="snum" style="color:var(--red)">${r.killChainStage+1}/13</div><div class="slbl">مرحلة Kill Chain</div></div>
          <div class="scell"><div class="snum" style="color:var(--grn)">${Math.round((r.techniques[0]?.confidence||0))}%</div><div class="slbl">أعلى ثقة</div></div>
        </div>

        <!-- Kill Chain visualization -->
        <div style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);padding:14px;margin-bottom:14px;overflow-x:auto;">
          <div style="font-size:9px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-bottom:12px;">سلسلة الهجوم (Kill Chain)</div>
          <div style="display:flex;align-items:center;min-width:700px;">${kcHTML}</div>
        </div>

        <!-- ATT&CK Matrix -->
        <div style="background:var(--s2);border:1px solid var(--b1);border-radius:var(--r8);padding:14px;margin-bottom:14px;overflow-x:auto;">
          <div style="font-size:9px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:2px;margin-bottom:12px;">مصفوفة ATT&CK — التكتيكات المُرتبطة</div>
          <svg viewBox="0 0 ${svgW} 45" width="100%" style="min-width:${svgW}px;overflow:visible;height:55px">${matSVG}</svg>
        </div>

        <!-- Techniques by tactic -->
        <div class="fhd">التقنيات المُكتشفة مرتبة حسب التكتيك (${r.total})</div>
        ${Object.entries(r.byTactic).map(([taId, tactic]) => {
          const tacInfo = r.TACTICS[taId]||{};
          return `<div style="background:var(--s2);border:1px solid var(--b1);border-right:3px solid ${tacInfo.color||'var(--pri)'};border-radius:var(--r8);padding:11px 13px;margin-bottom:6px;">
            <div style="font-size:10px;font-weight:700;color:${tacInfo.color||'var(--pri)'};margin-bottom:6px;font-family:var(--mono);">
              ${esc(taId)} · ${esc(tacInfo.ar||tactic.name||'')} / ${esc(tacInfo.name||'')}
            </div>
            ${(tactic.techniques||[]).map(tech => `
              <div style="display:flex;align-items:flex-start;gap:9px;padding:6px 0;border-bottom:1px solid var(--b1);">
                <span style="font-size:9px;font-family:var(--mono);color:${tacInfo.color||'var(--pri)'};font-weight:700;flex-shrink:0;padding:2px 6px;background:${tacInfo.color||'var(--pri)'}22;border-radius:3px;">${esc(tech.id)}</span>
                <div style="flex:1;">
                  <div style="font-size:11.5px;font-weight:600;color:var(--t1)">${esc(tech.name)}</div>
                  <div style="font-size:10px;color:var(--t3);margin-top:2px">${esc(tech.desc)}</div>
                </div>
                <div style="font-size:9px;font-family:var(--mono);color:${tech.confidence>60?'var(--red)':tech.confidence>30?'var(--amb)':'var(--grn)'};">${tech.confidence}%</div>
              </div>`).join('')}
          </div>`;
        }).join('')}

        <div class="chips">
          ${r.activeTactics.map(ta => `<span class="ch" style="background:${(r.TACTICS[ta]?.color||'#0ea5e9')}22;color:${r.TACTICS[ta]?.color||'#0ea5e9'};border:1px solid ${r.TACTICS[ta]?.color||'#0ea5e9'}44">${esc(r.TACTICS[ta]?.ar||ta)}</span>`).join('')}
        </div>
      </div>
    </div>`);
}
