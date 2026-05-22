/**
 * DFAS — Charts & Visualization Engine
 * SVG Donut · Bar · Sparkline · Gauge · Particle BG
 */
'use strict';

const DFAS_Charts = (() => {

  /* ── Donut Chart ── */
  function donut(el, segments, opts = {}) {
    const { size = 180, stroke = 28, label = '', sub = '' } = opts;
    const r = (size / 2) - stroke / 2;
    const cx = size / 2, cy = size / 2;
    const circ = 2 * Math.PI * r;
    let offset = 0;
    const total = segments.reduce((s, g) => s + g.value, 0) || 1;

    const paths = segments.map(seg => {
      const pct  = seg.value / total;
      const dash = pct * circ;
      const gap  = circ - dash;
      const path = `<circle cx="${cx}" cy="${cy}" r="${r}"
        fill="none" stroke="${seg.color}" stroke-width="${stroke}"
        stroke-dasharray="${dash.toFixed(2)} ${gap.toFixed(2)}"
        stroke-dashoffset="${(-offset * circ / total).toFixed(2)}"
        stroke-linecap="butt"
        style="transition:stroke-dasharray .8s cubic-bezier(.4,0,.2,1)"
        data-label="${seg.label}" data-val="${seg.value}">
        <title>${seg.label}: ${seg.value}</title>
      </circle>`;
      offset += seg.value;
      return path;
    }).join('');

    el.innerHTML = `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" style="transform:rotate(-90deg)">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="rgba(255,255,255,.05)" stroke-width="${stroke}"/>
      ${paths}
    </svg>
    <div class="donut-center">
      <div class="donut-lbl">${label}</div>
      <div class="donut-sub">${sub}</div>
    </div>`;
  }

  /* ── Bar Chart ── */
  function bars(el, data, opts = {}) {
    const { height = 120, color = '#0ea5e9', colors = null } = opts;
    if (!data || !data.length) { el.innerHTML = '<div class="chart-empty">لا توجد بيانات</div>'; return; }
    const max = Math.max(...data.map(d => d.total || d.value || 0), 1);

    const cols = data.map((d, i) => {
      const v   = d.total || d.value || 0;
      const pct = (v / max) * 100;
      const c   = colors ? colors[i % colors.length] : color;
      const lbl = d.label || '';
      return `<div class="bar-col">
        <div class="bar-val">${v || ''}</div>
        <div class="bar-wrap" style="height:${height}px">
          <div class="bar-fill" style="height:0%;background:${c};--target:${pct}%" data-pct="${pct}"></div>
        </div>
        <div class="bar-lbl">${lbl}</div>
      </div>`;
    }).join('');

    el.innerHTML = `<div class="bar-chart">${cols}</div>`;

    // Animate
    requestAnimationFrame(() => {
      el.querySelectorAll('.bar-fill').forEach(b => {
        setTimeout(() => { b.style.height = b.dataset.pct + '%'; }, 100);
      });
    });
  }

  /* ── Stacked Bar ── */
  function stackedBars(el, data, opts = {}) {
    const { height = 120 } = opts;
    if (!data || !data.length) { el.innerHTML = '<div class="chart-empty">لا توجد بيانات</div>'; return; }
    const max = Math.max(...data.map(d => (d.crit||0)+(d.warn||0)+(d.safe||0)), 1);

    const cols = data.map(d => {
      const total = (d.crit||0) + (d.warn||0) + (d.safe||0);
      const pc = v => ((v/max)*100).toFixed(1);
      return `<div class="bar-col">
        <div class="bar-val">${total||''}</div>
        <div class="bar-wrap" style="height:${height}px">
          <div class="bar-stack">
            <div style="height:0%;background:#ef4444;--t:${pc(d.crit||0)}%" class="bar-seg" data-pct="${pc(d.crit||0)}"></div>
            <div style="height:0%;background:#f59e0b;--t:${pc(d.warn||0)}%" class="bar-seg" data-pct="${pc(d.warn||0)}"></div>
            <div style="height:0%;background:#10b981;--t:${pc(d.safe||0)}%" class="bar-seg" data-pct="${pc(d.safe||0)}"></div>
          </div>
        </div>
        <div class="bar-lbl">${d.label||''}</div>
      </div>`;
    }).join('');

    el.innerHTML = `<div class="bar-chart">${cols}</div>`;
    requestAnimationFrame(() => {
      el.querySelectorAll('.bar-seg').forEach(b => {
        setTimeout(() => { b.style.height = b.dataset.pct + '%'; }, 150);
      });
    });
  }

  /* ── Gauge / Arc ── */
  function gauge(el, pct, color) {
    const r = 54, cx = 70, cy = 70;
    const circ = Math.PI * r; // half circle
    const dash  = (pct / 100) * circ;
    const gap   = circ - dash;
    el.innerHTML = `<svg viewBox="0 0 140 80" width="140" height="80">
      <path d="M16,70 A54,54 0 0,1 124,70" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="16" stroke-linecap="round"/>
      <path d="M16,70 A54,54 0 0,1 124,70" fill="none" stroke="${color}" stroke-width="16" stroke-linecap="round"
        stroke-dasharray="${dash.toFixed(1)} ${gap.toFixed(1)}"
        style="transition:stroke-dasharray .9s cubic-bezier(.4,0,.2,1)"/>
      <text x="70" y="64" text-anchor="middle" font-size="22" font-weight="700" fill="${color}" font-family="IBM Plex Mono">${pct}%</text>
    </svg>`;
  }

  /* ── Sparkline ── */
  function sparkline(el, values, color = '#0ea5e9') {
    if (!values || values.length < 2) return;
    const w = 120, h = 36;
    const max = Math.max(...values, 1);
    const pts = values.map((v, i) => {
      const x = (i / (values.length - 1)) * w;
      const y = h - (v / max) * h;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
    el.innerHTML = `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" style="overflow:visible">
      <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
  }

  /* ── Particle Background ── */
  function initParticles(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let W, H, pts;

    function resize() {
      W = canvas.width  = window.innerWidth;
      H = canvas.height = window.innerHeight;
      pts = Array.from({length: 55}, () => ({
        x  : Math.random() * W,
        y  : Math.random() * H,
        vx : (Math.random() - .5) * .35,
        vy : (Math.random() - .5) * .35,
        r  : Math.random() * 1.4 + .4
      }));
    }

    function draw() {
      ctx.clearRect(0, 0, W, H);
      pts.forEach(p => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > W) p.vx *= -1;
        if (p.y < 0 || p.y > H) p.vy *= -1;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(14,165,233,0.45)';
        ctx.fill();
      });

      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const dx = pts[i].x - pts[j].x;
          const dy = pts[i].y - pts[j].y;
          const dist = Math.sqrt(dx*dx + dy*dy);
          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(pts[i].x, pts[i].y);
            ctx.lineTo(pts[j].x, pts[j].y);
            ctx.strokeStyle = `rgba(14,165,233,${(1 - dist/120) * 0.18})`;
            ctx.lineWidth = .6;
            ctx.stroke();
          }
        }
      }
      requestAnimationFrame(draw);
    }

    resize();
    window.addEventListener('resize', resize);
    draw();
  }

  /* ── Animated Counter ── */
  function counter(el, target, duration = 1400, suffix = '') {
    const start = performance.now();
    function step(now) {
      const p = Math.min((now - start) / duration, 1);
      const ease = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(ease * target) + suffix;
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  return { donut, bars, stackedBars, gauge, sparkline, initParticles, counter };
})();
