import { useEffect } from 'react';
import { useRouter } from 'next/router';

/** Canonical investigation URL defaults to the evidence-backed overview. */
export default function InvestigationPage() {
  const router = useRouter();
  const id = typeof router.query.id === 'string' ? router.query.id : undefined;
  useEffect(() => {
    if (id) router.replace(`/investigations/${encodeURIComponent(id)}/overview`);
  }, [id, router]);
  return <div className="p-8 text-text-secondary" role="status">Loading investigation…</div>;
}
