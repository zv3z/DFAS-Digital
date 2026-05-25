/**
 * DFAS — Digital Forensics Analysis System
 * Database Layer — IndexedDB + LocalStorage fallback
 * ─────────────────────────────────────────────────
 */
'use strict';

const DFAS_DB = (() => {
  const DB_NAME    = 'DFAS_v2';
  const DB_VERSION = 2;
  let   db         = null;

  const STORES = {
    analyses : { keyPath:'id', autoIncrement:true, indexes:[
      {name:'type',   keyPath:'type',   opts:{unique:false}},
      {name:'ts',     keyPath:'ts',     opts:{unique:false}},
      {name:'threat', keyPath:'threat', opts:{unique:false}}
    ]},
    cases    : { keyPath:'caseId', autoIncrement:false, indexes:[
      {name:'status', keyPath:'status', opts:{unique:false}},
      {name:'ts',     keyPath:'ts',     opts:{unique:false}}
    ]},
    reports  : { keyPath:'reportId', autoIncrement:false, indexes:[
      {name:'caseId', keyPath:'caseId', opts:{unique:false}}
    ]},
    settings : { keyPath:'key', autoIncrement:false, indexes:[] }
  };

  /* ── Open / Upgrade ── */
  async function open() {
    if (db) return db;
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = e => {
        const d = e.target.result;
        for (const [name, cfg] of Object.entries(STORES)) {
          let store;
          if (!d.objectStoreNames.contains(name)) {
            store = d.createObjectStore(name, {
              keyPath      : cfg.keyPath,
              autoIncrement: cfg.autoIncrement
            });
          } else {
            store = e.target.transaction.objectStore(name);
          }
          cfg.indexes.forEach(idx => {
            if (!store.indexNames.contains(idx.name))
              store.createIndex(idx.name, idx.keyPath, idx.opts);
          });
        }
      };
      req.onsuccess  = e => { db = e.target.result; resolve(db); };
      req.onerror    = e => reject(e.target.error);
    });
  }

  /* ── Generic CRUD ── */
  async function tx(storeName, mode, fn) {
    const d = await open();
    return new Promise((resolve, reject) => {
      const transaction = d.transaction([storeName], mode);
      const store = transaction.objectStore(storeName);
      const req = fn(store);
      if (req && typeof req.onsuccess !== 'undefined') {
        req.onsuccess = e => resolve(e.target.result);
        req.onerror   = e => reject(e.target.error);
      } else {
        transaction.oncomplete = () => resolve(req);
        transaction.onerror    = e  => reject(e.target.error);
      }
    });
  }

  async function put(store, obj)    { return tx(store, 'readwrite', s => s.put(obj)); }
  async function get(store, key)    { return tx(store, 'readonly',  s => s.get(key)); }
  async function del(store, key)    { return tx(store, 'readwrite', s => s.delete(key)); }
  async function getAll(store, idx) {
    const d = await open();
    return new Promise((resolve, reject) => {
      const t  = d.transaction([store], 'readonly');
      const s  = t.objectStore(store);
      const src = idx ? s.index(idx.name).getAll(idx.range) : s.getAll();
      src.onsuccess = e => resolve(e.target.result);
      src.onerror   = e => reject(e.target.error);
    });
  }
  async function count(store) {
    const d = await open();
    return new Promise((resolve, reject) => {
      const req = d.transaction([store],'readonly').objectStore(store).count();
      req.onsuccess = e => resolve(e.target.result);
      req.onerror   = e => reject(e.target.error);
    });
  }
  async function clear(store) { return tx(store, 'readwrite', s => s.clear()); }

  /* ── High-level API ── */

  // ANALYSES
  async function saveAnalysis(record) {
    record.ts = record.ts || Date.now();
    return put('analyses', record);
  }
  async function getAnalyses(limit = 100) {
    const all = await getAll('analyses');
    return all.sort((a,b) => b.ts - a.ts).slice(0, limit);
  }
  async function getStats() {
    const all = await getAll('analyses');
    const stats = { total:0, crit:0, warn:0, safe:0, byType:{} };
    all.forEach(a => {
      stats.total++;
      if (a.threat === 'crit') stats.crit++;
      else if (a.threat === 'warn') stats.warn++;
      else stats.safe++;
      stats.byType[a.type] = (stats.byType[a.type]||0) + 1;
    });
    return stats;
  }
  async function getDailyStats(days = 7) {
    const all = await getAll('analyses');
    const now = Date.now();
    const result = [];
    for (let i = days-1; i >= 0; i--) {
      const dayStart = now - i*86400000;
      const dayEnd   = dayStart + 86400000;
      const recs = all.filter(a => a.ts >= (dayStart - 86400000) && a.ts < dayEnd);
      const d = new Date(dayStart);
      result.push({
        label : `${d.getDate()}/${d.getMonth()+1}`,
        total : recs.length,
        crit  : recs.filter(r => r.threat==='crit').length,
        warn  : recs.filter(r => r.threat==='warn').length,
        safe  : recs.filter(r => r.threat==='safe').length
      });
    }
    return result;
  }

  // CASES
  async function saveCase(c) {
    c.ts = c.ts || Date.now();
    if (!c.caseId) c.caseId = 'CASE-' + Date.now().toString(36).toUpperCase();
    return put('cases', c);
  }
  async function deleteCase(id)   { return del('cases', id); }
  async function getCases()       { const a = await getAll('cases'); return a.filter(c=>!c._deleted).sort((x,y)=>y.ts-x.ts); }
  async function getCase(id)      { return get('cases', id); }
  async function updateCase(id, patch) {
    const existing = await getCase(id);
    if (!existing) throw new Error('Case not found: ' + id);
    return put('cases', {...existing, ...patch, caseId:id});
  }

  // REPORTS
  async function saveReport(r) {
    r.ts = r.ts || Date.now();
    if (!r.reportId) r.reportId = 'RPT-' + Date.now().toString(36).toUpperCase();
    return put('reports', r);
  }
  async function getReports()     { const a = await getAll('reports'); return a.sort((x,y)=>y.ts-x.ts); }

  // SETTINGS
  async function getSetting(key, def = null) {
    const v = await get('settings', key);
    return v ? v.value : def;
  }
  async function setSetting(key, value) { return put('settings', {key, value}); }

  // EXPORT
  async function exportAll() {
    const [analyses, cases, reports] = await Promise.all([
      getAll('analyses'), getAll('cases'), getAll('reports')
    ]);
    return JSON.stringify({ exportedAt: new Date().toISOString(), analyses, cases, reports }, null, 2);
  }

  async function clearAll() {
    await Promise.all([clear('analyses'), clear('cases'), clear('reports')]);
  }

  return {
    open, saveAnalysis, getAnalyses, getStats, getDailyStats,
    saveCase, deleteCase, getCases, getCase, updateCase,
    saveReport, getReports,
    getSetting, setSetting,
    exportAll, clearAll, count
  };
})();
