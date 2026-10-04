import { useEffect, useState } from 'react';

export interface InvestigationStatusData {
  id: string;
  title?: string;
  status: string;
  subject?: string;
  sender?: string;
  verdict?: string;
  risk_score?: number;
  summary?: string;
  confidence?: number;
  confidence_level?: string;
  score_breakdown?: Record<string, number>;
  analysis_warnings?: string[];
  findings?: Array<{ id: string; severity: string; category: string; title: string; description: string; evidence_refs: string[]; }>;
  evidence?: Array<{ id: string; type: string; source: string; value: string; description: string; }>;
  auth_results?: Array<{ id: string; protocol: string; result: string; details?: Record<string, unknown>; }>;
  indicators?: Array<{ id: string; type: string; normalized_value: string; is_private: boolean; }>;
  hops?: Array<{ id: string; hop_number: number; from_host?: string; by_host?: string; ip_address?: string; timestamp?: string; }>;
  timeline?: Array<{ id: string; timestamp?: string; event_type: string; title: string; description: string; source: string; time_kind: string; }>;
}

export function useInvestigationStatus(id: string | undefined) {
  const [data, setData] = useState<InvestigationStatusData>();
  const [isLoading, setIsLoading] = useState(Boolean(id));
  const [error, setError] = useState<Error>();

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    fetch(`${process.env.NEXT_PUBLIC_API_URL || ''}/api/v1/investigations/${encodeURIComponent(id)}`)
      .then(async (response) => {
        if (!response.ok) throw new Error(`Failed to fetch investigation: ${response.status}`);
        return response.json();
      })
      .then((result) => {
        if (!cancelled) setData(result);
      })
      .catch((reason) => {
        if (!cancelled) setError(reason instanceof Error ? reason : new Error(String(reason)));
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [id]);

  return { data, isLoading, error };
}
