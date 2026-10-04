import React from 'react';
import Link from 'next/link';
import { clsx } from 'clsx';
import StatusBadge from './StatusBadge';
import SeverityBadge from './SeverityBadge';

export interface InvestigationRow {
  id: string;
  externalId: string;
  subject: string;
  sender: string;
  verdict: 'benign' | 'suspicious' | 'malicious' | 'unknown';
  riskScore: number;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  createdAt: string;
}

interface InvestigationTableProps {
  investigations: InvestigationRow[];
  isLoading?: boolean;
  onRowClick?: (id: string) => void;
  className?: string;
}

const columns = [
  { key: 'externalId', header: 'Investigation ID', width: 'w-48' },
  { key: 'subject', header: 'Subject', width: 'flex-1 min-w-0' },
  { key: 'sender', header: 'Sender', width: 'w-64' },
  { key: 'verdict', header: 'Verdict', width: 'w-36' },
  { key: 'riskScore', header: 'Risk', width: 'w-24' },
  { key: 'status', header: 'Status', width: 'w-32' },
  { key: 'createdAt', header: 'Created', width: 'w-40' },
];

export default function InvestigationTable({
  investigations,
  isLoading = false,
  onRowClick,
  className
}: InvestigationTableProps) {
  if (isLoading) {
    return (
      <div className={className}>
        <div className="glass-panel rounded-2xl overflow-hidden">
          <div className="p-4 md:p-5 border-b border-border-default/70 bg-bg-tertiary/30">
            <div className="flex items-center gap-3 text-text-secondary text-sm font-medium">
              {columns.map(col => (
                <div key={col.key} className={clsx('skeleton h-4', col.width)}>
                  <span className="sr-only">Loading...</span>
                </div>
              ))}
            </div>
          </div>
          <div className="divide-y divide-border-subtle">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="p-4">
                <div className="flex items-center gap-3">
                  {columns.map(col => (
                    <div key={`${i}-${col.key}`} className={clsx('skeleton h-5', col.width)} />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (investigations.length === 0) {
    return (
      <div className={className}>
        <div className="bg-bg-secondary border border-border-default rounded-lg p-12">
          <div className="text-center">
            <svg className="w-12 h-12 mx-auto text-text-tertiary mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            <h3 className="text-lg font-medium text-text-primary">No investigations found</h3>
            <p className="text-text-secondary mt-1">Start by uploading a suspicious email to analyze.</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={className}>
      <div className="bg-bg-secondary border border-border-default rounded-lg overflow-hidden">
        <div className="p-4 border-b border-border-default">
          <div className="flex items-center gap-3 text-text-secondary text-sm font-medium">
            {columns.map(col => (
              <div key={col.key} className={clsx('truncate', col.width)}>
                {col.header}
              </div>
            ))}
          </div>
        </div>
        <div className="divide-y divide-border-subtle">
          {investigations.map((investigation) => (
            <div
              key={investigation.id}
              className={clsx('p-4 md:p-5 transition-colors relative hover:bg-white/[0.025]', onRowClick && 'cursor-pointer')}
              onClick={() => onRowClick?.(investigation.id)}
            >
              <div className="flex items-center gap-3">
                <div className={clsx('truncate font-mono text-sm', columns[0].width)}>
                  <Link href={`/investigations/${investigation.id}`} className="text-accent-cyan hover:underline">
                    {investigation.externalId}
                  </Link>
                </div>
                <div className={clsx('truncate', columns[1].width)}>
                  <Link href={`/investigations/${investigation.id}`} className="text-text-primary hover:text-accent-cyan truncate block">
                    {investigation.subject || '(no subject)'}
                  </Link>
                </div>
                <div className={clsx('truncate text-text-secondary', columns[2].width)}>
                  {investigation.sender}
                </div>
                <div className={clsx(columns[3].width)}>
                  <StatusBadge label={investigation.verdict} type={investigation.verdict} size="sm" />
                </div>
                <div className={clsx('font-mono tabular-nums', columns[4].width)}>
                  <SeverityBadge
                    label={`${investigation.riskScore}`}
                    severity={
                      investigation.riskScore >= 80 ? 'critical' :
                      investigation.riskScore >= 60 ? 'high' :
                      investigation.riskScore >= 30 ? 'medium' : 'low'
                    }
                    size="sm"
                    showDot={false}
                  />
                </div>
                <div className={clsx(columns[5].width)}>
                  <StatusBadge label={investigation.status} type={investigation.status} size="sm" />
                </div>
                <div className={clsx('text-text-tertiary text-sm font-mono', columns[6].width)}>
                  {new Date(investigation.createdAt).toLocaleDateString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                  })}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}