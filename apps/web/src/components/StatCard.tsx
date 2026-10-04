import React from 'react';

interface StatCardProps {
  label: string;
  value: string | number;
  change?: string;
  changeType?: 'positive' | 'negative' | 'neutral';
  icon?: React.ReactNode;
  trend?: React.ReactNode;
  children?: React.ReactNode;
}

export default function StatCard({
  label,
  value,
  change,
  changeType = 'neutral',
  icon,
  trend,
  children
}: StatCardProps) {
  const changeColor = {
    positive: 'text-accent-green',
    negative: 'text-accent-red',
    neutral: 'text-text-muted',
  }[changeType];

  const defaultIcon = (
    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
    </svg>
  );

  return (
    <div className="glass-panel rounded-2xl p-5 relative overflow-hidden group">
      <div className="absolute -right-8 -top-8 w-24 h-24 rounded-full bg-accent-cyan/10 blur-2xl group-hover:bg-accent-cyan/20 transition-colors" />
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-text-secondary text-sm font-medium">{label}</p>
          <p className="text-3xl font-semibold text-text-primary mt-1 font-mono tracking-tight">{value}</p>
          {change && (
            <p className={`text-xs mt-1 flex items-center gap-1 ${changeColor}`}>
              {change}
            </p>
          )}
        </div>
        <div className="flex-shrink-0 w-11 h-11 rounded-xl bg-accent-cyan/10 ring-1 ring-accent-cyan/20 flex items-center justify-center text-accent-cyan">
          {icon || defaultIcon}
        </div>
      </div>
      {trend && (
        <div className="mt-4 pt-4 border-t border-border-default">
          {trend}
        </div>
      )}
      {children && (
        <div className="mt-4">{children}</div>
      )}
    </div>
  );
}