import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { UploadResponse } from '../api/types';

const STALE_TIME = 30_000;
const RETRY = 1;

export function useInvestigations(params: { page?: number; pageSize?: number; verdict?: string; status?: string } = {}) {
  return useQuery({
    queryKey: ['investigations', params],
    queryFn: () => api.investigations.list(params),
    staleTime: STALE_TIME,
    retry: RETRY,
    refetchOnWindowFocus: false,
  });
}

export function useInvestigation(id: string | undefined) {
  return useQuery({
    queryKey: ['investigation', id],
    queryFn: () => api.investigations.get(id!),
    enabled: !!id,
    staleTime: STALE_TIME,
    retry: RETRY,
    refetchOnWindowFocus: false,
  });
}

export function useUploadInvestigation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (file: File) => api.investigations.upload(file),
    onSuccess: (data: UploadResponse) => {
      queryClient.invalidateQueries({ queryKey: ['investigations'] });
    },
  });
}

export function useUploadInvestigationWithCallback(
  onUploadSuccess?: (data: UploadResponse) => void,
) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (file: File) => api.investigations.upload(file),
    onSuccess: (data: UploadResponse) => {
      queryClient.invalidateQueries({ queryKey: ['investigations'] });
      onUploadSuccess?.(data);
    },
  });
}

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: () => api.health.ready(),
    staleTime: 10_000,
    refetchInterval: 30_000,
    retry: 0,
  });
}