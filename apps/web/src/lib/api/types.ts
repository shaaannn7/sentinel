/**
 * Shared TypeScript types for SENTINEL API
 * Matches backend schemas exactly for type safety
 */

export type Verdict = 'benign' | 'suspicious' | 'malicious' | 'unknown';
export type InvestigationStatus = 'pending' | 'processing' | 'completed' | 'failed';
export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface Indicator {
  id: string;
  type: string;
  value: string;
  confidence: number;
  tags: string[];
  source: string;
  firstSeen: string;
  lastSeen: string;
  threatIntel?: ThreatIntelMatch;
}

export interface ThreatIntelMatch {
  source: string;
  malicious: boolean;
  categories: string[];
  confidence: number;
  details: Record<string, unknown>;
}

export interface AuthResult {
  domain: string;
  spf: AuthCheckResult;
  dkim: AuthCheckResult;
  dmarc: AuthCheckResult;
  overall: 'pass' | 'fail' | 'none';
}

export interface AuthCheckResult {
  result: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
  details: string;
  aligned: boolean;
}

export interface ReceivedHop {
  index: number;
  from: string;
  by: string;
  via: string;
  with: string;
  id: string;
  for: string;
  timestamp: string;
  delayMs?: number;
  geo?: GeoInfo;
  asn?: AsnInfo;
}

export interface GeoInfo {
  country: string;
  countryCode: string;
  city: string;
  latitude: number;
  longitude: number;
  isp: string;
  org: string;
}

export interface AsnInfo {
  number: number;
  name: string;
  route: string;
  domain: string;
  type: string;
}

export interface EmailHeader {
  name: string;
  value: string;
}

export interface EmailArtifact {
  id: string;
  messageId: string;
  subject: string;
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  replyTo: string[];
  date: string;
  headers: EmailHeader[];
  textBody?: string;
  htmlBody?: string;
  attachments: Attachment[];
  indicators: Indicator[];
  authResults: AuthResult[];
  receivedHops: ReceivedHop[];
}

export interface Attachment {
  id: string;
  filename: string;
  contentType: string;
  size: number;
  sha256: string;
  magicBytes: string;
  isSuspicious: boolean;
  suspiciousReasons: string[];
  extractedPath?: string;
}

export interface InvestigationSummary {
  id: string;
  externalId: string;
  status: InvestigationStatus;
  subject: string;
  sender: string;
  verdict: Verdict;
  riskScore: number;
  confidence: number;
  summary: string;
  createdAt: string;
  updatedAt: string;
}

export interface InvestigationDetail extends InvestigationSummary {
  artifact: EmailArtifact;
}

export interface InvestigationListResponse {
  investigations: InvestigationSummary[];
  total: number;
  page: number;
  pageSize: number;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  uptime: number;
  checks: Record<string, { status: 'pass' | 'fail'; latencyMs: number }>;
}

export interface ReadyResponse {
  ready: boolean;
  checks: Record<string, boolean>;
}

export interface UploadResponse {
  investigationId: string;
  externalId: string;
  status: InvestigationStatus;
  message: string;
}