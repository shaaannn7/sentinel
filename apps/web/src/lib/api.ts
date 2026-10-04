export interface Investigation {
  id: string;
  external_id?: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  result?: unknown;
  error?: string;
  created_at?: string;
  updated_at?: string;
  subject?: string;
  sender?: string;
  verdict?: string;
  risk_score?: number;
  confidence?: number;
  confidence_level?: string;
  summary?: string;
  score_breakdown?: Record<string, number>;
  analysis_warnings?: string[];
  evidence?: Evidence[];
  findings?: Finding[];
  timeline?: TimelineEvent[];
  auth_results?: AuthResult[];
  indicators?: Indicator[];
  hops?: ReceivedHop[];
  artifacts?: Artifact[];
}

export interface Evidence { id: string; type: string; source: string; value: string; description: string; metadata_json?: Record<string, unknown>; }
export interface Finding { id: string; severity: string; category: string; title: string; description: string; confidence: string; evidence_refs: string[]; points: number; source: string; }
export interface TimelineEvent { id: string; timestamp?: string; event_type: string; title: string; description: string; source: string; time_kind: string; }
export interface AuthResult { id: string; protocol: string; result: string; details?: Record<string, unknown>; }
export interface Indicator { id: string; type: string; normalized_value: string; raw_value: string; threat_verdict: string; is_private: boolean; }
export interface ReceivedHop { id: string; hop_number: number; from_host?: string; by_host?: string; ip_address?: string; timestamp?: string; }
export interface Artifact { id: string; filename: string; file_size: number; sha256: string; plain_body?: string; html_body?: string; attachments?: Array<{ id: string; filename: string; mime_type: string; size: number; sha256: string; is_suspicious: boolean; }>; }

const API_URL = process.env.NEXT_PUBLIC_API_URL || '';

function getAuthHeaders(): Record<string, string> {
  const authKey = typeof window !== 'undefined'
    ? localStorage.getItem('sentinel_api_key') || process.env.NEXT_PUBLIC_API_KEY || ''
    : process.env.NEXT_PUBLIC_API_KEY || '';
  return authKey ? { 'X-API-Key': authKey } : {};
}

export async function createInvestigation(file: File): Promise<Investigation> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_URL}/api/v1/investigations`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Upload failed' }));
    throw new Error(error.detail || error.message || `HTTP ${response.status}`);
  }

  return response.json();
}

export async function getInvestigation(id: string): Promise<Investigation> {
  const response = await fetch(`${API_URL}/api/v1/investigations/${encodeURIComponent(id)}`, {
    headers: getAuthHeaders(),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Fetch failed' }));
    throw new Error(error.detail || error.message || `HTTP ${response.status}`);
  }

  return response.json();
}

export async function listInvestigations(): Promise<{ total: number; items: Investigation[] }> {
  const response = await fetch(`${API_URL}/api/v1/investigations`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Fetch failed' }));
    throw new Error(error.detail || error.message || `HTTP ${response.status}`);
  }
  return response.json();
}

export async function pollInvestigation(
  id: string,
  options: {
    intervalMs?: number;
    timeoutMs?: number;
    onUpdate?: (investigation: Investigation) => void;
  } = {}
): Promise<Investigation> {
  const { intervalMs = 2000, timeoutMs = 60000, onUpdate } = options;
  const startTime = Date.now();

  while (true) {
    const investigation = await getInvestigation(id);

    if (onUpdate) {
      onUpdate(investigation);
    }

    if (investigation.status === 'completed' || investigation.status === 'failed') {
      return investigation;
    }

    if (Date.now() - startTime > timeoutMs) {
      throw new Error(`Polling timeout after ${timeoutMs}ms`);
    }

    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}