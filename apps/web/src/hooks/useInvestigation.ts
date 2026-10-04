// src/hooks/useInvestigation.ts

import { useState, useCallback, useEffect } from "react";

/**
 * Types representing an investigation entity.
 */
export interface Investigation {
  /** Unique identifier of the investigation */
  id: string;
  /** Current status of the investigation */
  status: InvestigationStatus;
  /** Optional human‑readable title */
  title?: string;
  /** Optional description provided at creation */
  description?: string;
  /** When the investigation was created (ISO string) */
  createdAt: string;
  /** When the investigation was last updated (ISO string) */
  updatedAt: string;
}

/** All possible statuses a investigation can be in. */
export type InvestigationStatus =
  | "idle"
  | "pending"
  | "in_progress"
  | "completed"
  | "failed";

/** Payload required to create a new investigation */
export interface CreateInvestigationInput {
  /** Title for the investigation */
  title: string;
  /** Optional longer description */
  description?: string;
}

/** Result type returned by the create hook */
export interface UseCreateInvestigationResult {
  /** Function to trigger creation */
  mutate: (input: CreateInvestigationInput) => Promise<void>;
  /** Latest created investigation (or undefined) */
  data?: Investigation;
  /** Loading flag while request is in flight */
  loading: boolean;
  /** Error object if request failed */
  error?: Error;
}

/**
 * Hook to create an investigation. It abstracts the async request and provides a
 * simple mutate function together with loading / error state.
 */
export function useCreateInvestigation(): UseCreateInvestigationResult {
  const [data, setData] = useState<Investigation>();
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<Error>();

  const mutate = useCallback(async (input: CreateInvestigationInput) => {
    setLoading(true);
    setError(undefined);
    try {
      const response = await fetch("/api/v1/investigations", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(input),
      });

      if (!response.ok) {
        const msg = `Failed to create investigation: ${response.status}`;
        throw new Error(msg);
      }

      const result: Investigation = await response.json();
      setData(result);
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setLoading(false);
    }
  }, []);

  return { mutate, data, loading, error };
}

/** Result type for the status hook */
export interface UseInvestigationStatusResult {
  /** Current status */
  status: InvestigationStatus | undefined;
  /** Loading flag while fetching */
  loading: boolean;
  /** Error object if request failed */
  error?: Error;
}

/**
 * Hook to fetch the status of an investigation by its id. It polls the
 * endpoint every 5 seconds to keep the status up‑to‑date.
 */
export function useInvestigationStatus(
  investigationId: string | undefined,
): UseInvestigationStatusResult {
  const [status, setStatus] = useState<InvestigationStatus>();
  const [loading, setLoading] = useState<boolean>(!!investigationId);
  const [error, setError] = useState<Error>();

  const fetchStatus = useCallback(async () => {
    if (!investigationId) return;
    try {
      const res = await fetch(`/api/v1/investigations/${investigationId}`);
      if (!res.ok) {
        throw new Error(`Failed to fetch status: ${res.status}`);
      }
      const data: { status: InvestigationStatus } = await res.json();
      setStatus(data.status);
      setError(undefined);
    } catch (e) {
      setError(e instanceof Error ? e : new Error(String(e)));
    } finally {
      setLoading(false);
    }
  }, [investigationId]);

  // Initial fetch and poll every 5 seconds while an id is present.
  useEffect(() => {
    if (!investigationId) return;
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, [investigationId, fetchStatus]);

  return { status, loading, error };
}
