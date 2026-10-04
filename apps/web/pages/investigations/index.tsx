import AppShell from '../../src/components/AppShell';
import InvestigationTable from '../../src/components/InvestigationTable';
import { useInvestigations } from '../../src/lib/hooks/useInvestigation';
import { listInvestigations } from '../../src/lib/api';
import { useEffect, useState } from 'react';
import type { InvestigationRow } from '../../src/components/InvestigationTable';

export default function InvestigationsPage() {
  const { data, isLoading, error } = useInvestigations();
  const [fallbackItems, setFallbackItems] = useState<InvestigationRow[]>([]);
  const [fallbackLoading, setFallbackLoading] = useState(false);

  useEffect(() => {
    if (!data && !error) {
      setFallbackLoading(true);
      listInvestigations()
        .then((response) => {
          const items = (response.items || []) as Array<any>;
          setFallbackItems(items.map((item) => ({
            id: item.id,
            externalId: item.external_id || item.id,
            subject: item.subject || '',
            sender: item.sender || '',
            verdict: (item.verdict || 'unknown') as InvestigationRow['verdict'],
            riskScore: item.risk_score || 0,
            status: item.status as InvestigationRow['status'],
            createdAt: item.created_at || new Date().toISOString(),
          })));
        })
        .catch(() => {
          // Fallback error ignored - the query hook handles its own error state
        })
        .finally(() => setFallbackLoading(false));
    }
  }, [data, error]);

  const items = data?.investigations?.map((inv) => ({
    id: inv.id,
    externalId: inv.externalId,
    subject: inv.subject || '',
    sender: inv.sender || '',
    verdict: inv.verdict,
    riskScore: inv.riskScore,
    status: inv.status,
    createdAt: inv.createdAt,
  })) || fallbackItems;

  const loading = isLoading || fallbackLoading;

  return (
    <AppShell>
      <div className="mx-auto max-w-7xl px-6 py-10">
        <h1 className="text-3xl font-semibold">Investigations</h1>
        <p className="mt-2 text-text-secondary">Evidence-backed email investigations.</p>
        {error && <p className="mt-4 text-accent-red" role="alert">{error.message}</p>}
        <InvestigationTable investigations={items} isLoading={loading} className="mt-8" />
      </div>
    </AppShell>
  );
}