import React from 'react';

type SeverityType = 'low' | 'medium' | 'high' | 'critical';

interface SeverityBadgeProps {
  label: string;
  severity: SeverityType;
  size?: 'sm' | 'md' | 'lg';
  showDot?: boolean;
}

const severityColors: Record<SeverityType, string> = {
  low: 'bg-accent-green/10 text-accent-green border-accent-green/30',
  medium: 'bg-accent-amber/10 text-accent-amber border-accent-amber/30',
  high: 'bg-accent-red/10 text-accent-red border-accent-red/30',
  critical: 'bg-accent-red/20 text-accent-red border-accent-red/40',
};

const sizeClasses = {
  sm: 'px-2 py-0.5 text-xs',
  md: 'px-2.5 py-1 text-sm',
  lg: 'px-3 py-1.5 text-base',
};

const dotSize = {
  sm: 'w-1.5 h-1.5',
  md: 'w-2 h-2',
  lg: 'w-2.5 h-2.5',
};

export default function SeverityBadge({
  label,
  severity,
  size = 'md',
  showDot = true
}: SeverityBadgeProps) {
  const colorClass = severityColors[severity];
  const dotClass = dotSize[size];

  return (
    <span className={`inline-flex items-center gap-1.5 font-medium border rounded-full ${sizeClasses[size]} ${colorClass}`}>
      {showDot && (
        <span className={`${dotClass} rounded-full ${colorClass.replace('bg-', 'bg-').replace('border-', 'bg-').replace('/10', '/20')}`} />
      )}
      {label}
    </span>
  );
}