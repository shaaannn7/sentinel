import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';

export interface BrainStatus {
  version: string;
  architecture: string;
  model_loaded: boolean;
  metrics: {
    accuracy: number;
    macro_f1: number;
    n_train: number;
    n_test: number;
    n_features: number;
    trained_at: string;
    per_class: Record<string, { precision: number; recall: number; f1: number }>;
  };
  ensemble_weights: {
    ml_classifier: number;
    deterministic_rules: number;
    threat_memory: number;
  };
  thresholds: Record<string, number>;
  memory: {
    total_records: number;
    threat_senders: number;
    threat_domains: number;
    threat_url_patterns: number;
    confirmed_safe: number;
    confirmed_threat: number;
    created_at: string;
  };
}

export interface BrainExplanation {
  investigation_id: string;
  verdict: string;
  risk_score: number;
  confidence: string;
  ml_label: string;
  ml_confidence: number;
  narrative: string;
  top_features: Array<{
    name: string;
    value: number;
    importance: number;
    direction: string;
    description: string;
  }>;
  top_rules: Array<{
    rule_id: string;
    signal_type: string;
    severity: string;
    points: number;
    description: string;
  }>;
  raw_proba: Record<string, number>;
}

export function useBrainStatus() {
  return useQuery<BrainStatus>({
    queryKey: ['brain', 'status'],
    queryFn: () => api.brain.status(),
    refetchInterval: 15000,
  });
}

export function useBrainExplain(investigationId?: string) {
  return useQuery<BrainExplanation>({
    queryKey: ['brain', 'explain', investigationId],
    queryFn: () => api.brain.explain(investigationId!),
    enabled: Boolean(investigationId),
    staleTime: 60000,
  });
}

export function useBrainRetrain() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.brain.retrain(),
    onSuccess: () => {
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ['brain', 'status'] });
      }, 3000);
    },
  });
}
