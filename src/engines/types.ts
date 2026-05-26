/**
 * DFAS Engine Types — TypeScript interfaces for all analysis results
 */

export type ThreatLevel = "crit" | "warn" | "safe";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Finding {
  sev: Severity;
  rule?: string;
  label?: string;
  det: string;
  ev?: string;
  cat?: string;
}

export interface EngineResult {
  pct: number;
  threat: ThreatLevel;
  findings?: Finding[];
  indicators?: Finding[];
}

/* MOD-01 Phishing */
export interface PhishingResult extends EngineResult {
  score: number;
  findings: Finding[];
  meta: { words: number; exclamations: number; urls: string[]; foreignTokens: number; lines: number };
}

/* MOD-02 URL */
export interface UrlResult extends EngineResult {
  score: number;
  findings: Finding[];
  parsed: { protocol: string; host: string; hostname: string; path: string; query: string; hash: string; port: string; ok: boolean };
  entropy: number;
}

/* MOD-03 Image */
export interface ImageResult extends EngineResult {
  indicators: Finding[];
  exifTable: { k: string; v: string; flag: string }[];
  chips: string[];
  name: string;
  size: string;
  type: string;
}

/* MOD-04 Email */
export interface EmailResult extends EngineResult {
  score: number;
  findings: Finding[];
  headers: Record<string, string>;
  auth: { spf: string; dkim: string; dmarc: string };
  hops: { hop: number; from: string; by: string; ts: string }[];
}

/* MOD-05 Hash */
export interface HashResult {
  sha256: string;
  sha1: string;
  md5: string;
  length?: number;
  bytes?: number;
  entropy?: number;
  size?: number;
  type?: string;
  name?: string;
  threat?: ThreatLevel;
  pct?: number;
  knownMalware?: boolean;
}

/* MOD-06 IOC */
export interface IOCResult extends EngineResult {
  results: { id: string; cat: string; sev: Severity; label: string; count: number; samples: { value: string; extra: string }[] }[];
  stats: { total: number; byCategory: Record<string, number>; bySeverity: Record<string, number> };
  extracted: Record<string, string[]>;
}

/* MOD-07 Stego */
export interface StegoResult extends EngineResult {
  indicators: Finding[];
  stats: Record<string, unknown>;
  realFile: boolean;
}

/* MOD-08 Timeline */
export interface TimelineResult {
  events: { raw: string; ts: number; date: Date; fmt: string; context: string }[];
  anomalies: unknown[];
  total: number;
  span: string;
  earliest?: Date;
  latest?: Date;
  threat: ThreatLevel;
  pct: number;
}

/* MOD-09 Network Log */
export interface NetLogResult extends EngineResult {
  findings: Finding[];
  stats: { totalReq: number; totalLines: number; parsed: number; totalBytes: number; topIPs: [string, number][]; statusMap: Record<number, number>; exploitPaths: number; scannerCount: number };
}

/* MOD-10 MITRE ATT&CK */
export interface MitreResult {
  techniques: { id: string; name: string; tactic: string; desc: string; confidence: number }[];
  byTactic: Record<string, { name: string; color: string; ar: string; id: string; techniques: unknown[] }>;
  total: number;
  tacticCount: number;
  killChainStage: number;
  TACTICS: Record<string, { name: string; color: string; ar: string }>;
  activeTactics: string[];
  threat: ThreatLevel;
  pct: number;
}

/* MOD-11 Memory Forensics (Volatility-inspired) */
export interface MemoryResult extends EngineResult {
  findings: Finding[];
  isVolatilityOutput: boolean;
  processCount: number;
  stats: {
    totalFindings: number;
    critical: number;
    high: number;
    injectionIndicators: number;
  };
}

/* MOD-12 Disk Image Analyzer (Sleuth Kit-inspired) */
export interface DiskResult extends EngineResult {
  findings: Finding[];
  detectedFS: string;
  entropy?: number;
  fileSize?: number;
  isTSKOutput?: boolean;
  stats: {
    totalFindings: number;
    critical?: number;
    high?: number;
  };
}

/* MOD-13 PCAP / Network Traffic Analyzer (Tshark-inspired) */
export interface PcapResult extends EngineResult {
  findings: Finding[];
  stats: {
    totalPackets: number | null;
    uniqueIPs: number;
    badIPs: number;
    beaconTargets: number;
  };
}

/* MOD-14 Endpoint Telemetry (Velociraptor-inspired) */
export interface EndpointResult extends EngineResult {
  findings: Finding[];
  stats: {
    totalFindings: number;
    critical: number;
    high: number;
    persistenceIndicators: number;
    credentialIndicators: number;
    mitreMapping: string[];
  };
}

export type AnyEngineResult = PhishingResult | UrlResult | ImageResult | EmailResult | HashResult | IOCResult | StegoResult | TimelineResult | NetLogResult | MitreResult | MemoryResult | DiskResult | PcapResult | EndpointResult;
