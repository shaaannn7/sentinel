import React from 'react';

type VerdictType = 'benign' | 'suspicious' | 'malicious' | 'unknown';
type StatusType = 'pending' | 'processing' | 'completed' | 'failed';

interface StatusBadgeProps {
  label: string;
  type: VerdictType | StatusType;
  size?: 'sm' | 'md' | 'lg';
}

const verdictColors: Record<VerdictType, string> = {
  benign: 'bg-accent-green/10 text-accent-green border-accent-green/30',
  suspicious: 'bg-accent-amber/10 text-accent-amber border-accent-amber/30',
  malicious: 'bg-accent-red/10 text-accent-red border-accent-red/30',
  unknown: 'bg-text-muted/10 text-text-secondary border-text-muted/30',
};

const statusColors: Record<StatusType, string> = {
  pending: 'bg-text-muted/10 text-text-secondary border-text-muted/30',
  processing: 'bg-accent-cyan/10 text-accent-cyan border-accent-cyan/30',
  completed: 'bg-accent-green/10 text-accent-green border-accent-green/30',
  failed: 'bg-accent-red/10 text-accent-red border-accent-red/30',
};

const sizeClasses = {
  sm: 'px-2 py-0.5 text-xs',
  md: 'px-2.5 py-1 text-sm',
  lg: 'px-3 py-1.5 text-base',
};

export default function StatusBadge({ label, type, size = 'md' }: StatusBadgeProps) {
  const colorClass = verdictColors[type as VerdictType] || statusColors[type as StatusType] || verdictColors.unknown;

  return (
    <span className={`inline-flex items-center font-medium border rounded-full ${sizeClasses[size]} ${colorClass}`}>
      {label}
    </span>
  );
}
