import type {
  InvestigationListResponse,
  InvestigationDetail,
  UploadResponse,
  HealthResponse,
  ReadyResponse,
} from './types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public details?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const config: RequestInit = {
    headers: {
      ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
      ...options.headers,
    },
    ...options,
  };

  const response = await fetch(url, config);

  if (!response.ok) {
    let errorBody: unknown;
    try {
      errorBody = await response.json();
    } catch {
      errorBody = await response.text();
    }
    throw new ApiError(
      `API error: ${response.statusText}`,
      response.status,
      errorBody
    );
  }

  return response.json();
}

function normalizeInvestigationDetail(raw: any): InvestigationDetail {
  const firstArtifact = raw.artifacts?.[0] || {};
  return {
    id: raw.id,
    externalId: raw.external_id || raw.id,
    status: raw.status || 'pending',
    subject: raw.subject || '',
    sender: raw.sender || '',
    verdict: raw.verdict || 'unknown',
    riskScore: raw.risk_score ?? 0,
    confidence: raw.confidence ?? 0,
    summary: raw.summary || '',
    createdAt: raw.created_at || new Date().toISOString(),
    updatedAt: raw.updated_at || new Date().toISOString(),
    artifact: {
      id: firstArtifact.id || raw.id,
      messageId: firstArtifact.message_id || '',
      subject: raw.subject || '',
      from: raw.sender || '',
      to: [],
      cc: [],
      bcc: [],
      replyTo: [],
      date: raw.created_at || new Date().toISOString(),
      headers: (firstArtifact.headers || []).map((h: any) => ({ name: h.name, value: h.value })),
      textBody: firstArtifact.plain_body || '',
      htmlBody: firstArtifact.html_body || '',
      attachments: (firstArtifact.attachments || []).map((a: any) => ({
        id: a.id || a.filename,
        filename: a.filename,
        contentType: a.mime_type,
        size: a.size,
        sha256: a.sha256,
        magicBytes: a.magic_bytes || '',
        isSuspicious: a.is_suspicious || false,
        suspiciousReasons: [],
      })),
      indicators: (raw.indicators || []).map((i: any) => ({
        id: i.id,
        type: i.type,
        value: i.normalized_value || i.raw_value,
        confidence: i.reputation_score || 0,
        tags: [i.threat_verdict].filter(Boolean),
        source: 'email',
        firstSeen: '',
        lastSeen: '',
      })),
      authResults: (raw.auth_results || []).map((auth: any) => ({
        domain: auth.details?.header_d || auth.details?.d || raw.sender?.split('@')[1] || 'unknown',
        spf: { result: auth.protocol === 'SPF' ? auth.result : 'none', details: JSON.stringify(auth.details || {}), aligned: true },
        dkim: { result: auth.protocol === 'DKIM' ? auth.result : 'none', details: JSON.stringify(auth.details || {}), aligned: true },
        dmarc: { result: auth.protocol === 'DMARC' ? auth.result : 'none', details: JSON.stringify(auth.details || {}), aligned: true },
        overall: auth.result === 'pass' ? 'pass' : auth.result === 'fail' ? 'fail' : 'none',
      })),
      receivedHops: (raw.hops || []).map((hop: any) => ({
        index: hop.hop_number,
        from: hop.from_host || 'unknown',
        by: hop.by_host || 'unknown',
        via: '',
        with: '',
        id: hop.id,
        for: '',
        timestamp: hop.timestamp || '',
      })),
    },
  };
}

export const api = {
  health: {
    live: () => request<{ status: string; timestamp: string }>('/health'),
    ready: () => request<ReadyResponse>('/ready'),
    detailed: () => request<HealthResponse>('/health'),
  },

  investigations: {
    list: async (params: { page?: number; pageSize?: number; verdict?: string; status?: string } = {}): Promise<InvestigationListResponse> => {
      const skip = ((params.page || 1) - 1) * (params.pageSize || 50);
      const limit = params.pageSize || 50;
      const searchParams = new URLSearchParams();
      searchParams.set('skip', String(skip));
      searchParams.set('limit', String(limit));
      if (params.verdict) searchParams.set('verdict', params.verdict);
      if (params.status) searchParams.set('status', params.status);
      const qs = searchParams.toString();
      const res = await request<{ total: number; items: any[] }>(`/api/v1/investigations?${qs}`);
      return {
        investigations: (res.items || []).map((item) => ({
          id: item.id,
          externalId: item.external_id || item.id,
          status: item.status,
          subject: item.subject || '',
          sender: item.sender || '',
          verdict: item.verdict,
          riskScore: item.risk_score || 0,
          confidence: item.confidence || 0,
          summary: item.summary || '',
          createdAt: item.created_at,
          updatedAt: item.updated_at,
        })),
        total: res.total,
        page: params.page || 1,
        pageSize: limit,
      };
    },

    get: async (id: string): Promise<InvestigationDetail> => {
      const res = await request<any>(`/api/v1/investigations/${encodeURIComponent(id)}`);
      return normalizeInvestigationDetail(res);
    },

    upload: async (file: File): Promise<UploadResponse> => {
      const formData = new FormData();
      formData.append('file', file);
      const res = await request<any>('/api/v1/investigations', {
        method: 'POST',
        body: formData,
      });
      return {
        investigationId: res.id,
        externalId: res.external_id || res.id,
        status: res.status,
        message: 'Investigation created successfully',
      };
    },
  },

  brain: {
    status: async (): Promise<any> => {
      return request<any>('/api/v1/brain/status');
    },
    explain: async (investigationId: string, topN: number = 10): Promise<any> => {
      return request<any>(`/api/v1/brain/explain/${encodeURIComponent(investigationId)}?top_n=${topN}`);
    },
    retrain: async (): Promise<{ status: string; message: string }> => {
      return request<{ status: string; message: string }>('/api/v1/brain/retrain', {
        method: 'POST',
      });
    },
  },
};

