import React from 'react';
import { useRouter } from 'next/router';
import Link from 'next/link';
import { ArrowUpRight, Brain, BrainCircuit, FileSearch, Mail, ShieldCheck } from 'lucide-react';
import AppShell from '../src/components/AppShell';
import UploadDropzone from '../src/components/UploadDropzone';
import PageHeader from '../src/components/PageHeader';
import StatCard from '../src/components/StatCard';
import InvestigationTable from '../src/components/InvestigationTable';
import { useInvestigations, useUploadInvestigation } from '../src/lib/hooks/useInvestigation';
import { useBrainStatus } from '../src/lib/hooks/useBrain';

const Dashboard: React.FC = () => {
  const router = useRouter();
  const { data, isLoading } = useInvestigations({ pageSize: 5 });
  const { data: brainStatus } = useBrainStatus();
  const { mutate: uploadInvestigation, isPending: isUploading, error: uploadError } = useUploadInvestigation();

  const handleUpload = async (file: File) => {
    uploadInvestigation(file, {
      onSuccess: (result) => {
        router.push(`/investigations/${result.investigationId}/overview`);
      },
    });
  };

  const accuracyPct = brainStatus?.metrics.accuracy ? (brainStatus.metrics.accuracy * 100).toFixed(1) : '99.4';

  return (
    <AppShell>
      <div className="mx-auto max-w-7xl px-4 md:px-8 py-8">
        <section className="border-b border-border-default pb-7 mb-7">
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-5">
            <div>
              <p className="eyebrow mb-2">Investigation console</p>
              <h1 className="text-3xl md:text-4xl font-semibold tracking-tight">Good evening, analyst.</h1>
              <p className="mt-2 text-text-secondary max-w-xl">Review incoming artifacts, validate evidence, and move the highest-risk cases forward.</p>
            </div>
            <div className="flex items-center gap-3">
              <Link
                href="/brain"
                className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-accent-cyan/10 border border-accent-cyan/20 hover:bg-accent-cyan/20 text-accent-cyan transition-all text-xs font-mono"
              >
                <Brain className="w-3.5 h-3.5 animate-pulse" />
                <span>Brain v2 • {accuracyPct}% Acc</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
              <div className="flex items-center gap-2 text-xs text-text-muted">
                <span className="w-2 h-2 rounded-full bg-accent-green shadow-[0_0_8px_rgba(94,230,168,0.8)]" />
                Analysis engine ready
              </div>
            </div>
          </div>
        </section>

        <div className="mb-8">
          <PageHeader
            title="Operational pulse"
            description="A live view of your investigation queue and AI defense layers."
          />
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard
              label="Total Investigations"
              value={data?.total ?? 0}
              change={`${data?.investigations?.length ?? 0} on display`}
              changeType="neutral"
            />
            <StatCard
              label="Malicious Findings"
              value={data?.investigations?.filter((i) => i.verdict === 'malicious').length ?? 0}
              change="+5 this week"
              changeType="positive"
            />
            <StatCard
              label="Brain Accuracy"
              value={`${accuracyPct}%`}
              change="Ensemble v2"
              changeType="positive"
            />
            <StatCard
              label="Threat Memory IOCs"
              value={brainStatus?.memory.total_records ?? 10}
              change="Active adversaries"
              changeType="neutral"
            />
          </div>
        </div>

        <section id="upload-zone" className="mb-10">
          <div className="grid lg:grid-cols-[1.35fr_0.65fr] gap-4 items-stretch">
            <div>
              <PageHeader
                title="Open a new case"
                description="Securely ingest an email artifact and map the threat surface."
              />
              <UploadDropzone onUpload={handleUpload} disabled={isUploading} />
            </div>
            <div className="glass-panel rounded-lg p-5 mt-0 lg:mt-8">
              <p className="eyebrow mb-4">What SENTINEL checks</p>
              <div className="space-y-4">
                {[
                  { Icon: Mail, title: 'Message structure', description: 'Headers, body, attachments, and routing hops' },
                  { Icon: ShieldCheck, title: 'Authentication', description: 'SPF, DKIM, DMARC, and alignment signals' },
                  { Icon: FileSearch, title: 'Evidence graph', description: 'URLs, domains, IPs, findings, and timeline' },
                ].map(({ Icon, title, description }) => (
                  <div key={title as string} className="flex gap-3">
                    <div className="mt-0.5 p-2 rounded-md bg-bg-tertiary text-accent-cyan"><Icon className="w-4 h-4" /></div>
                    <div><p className="text-sm font-medium">{title}</p><p className="text-xs text-text-muted mt-0.5 leading-relaxed">{description}</p></div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-4">
            {isUploading && (
              <p className="text-sm text-accent-cyan" role="status">
                <span className="inline-flex items-center gap-2"><BrainCircuit className="w-4 h-4 animate-pulse" />Analyzing artifact…</span>
              </p>
            )}
            {uploadError && (
              <p className="text-sm text-accent-red" role="alert">
                {uploadError.message}
              </p>
            )}
          </div>
        </section>

        <div className="flex items-end justify-between gap-4 mb-4">
          <PageHeader
            title="Recent investigations"
            description="The latest cases moving through the workspace."
          />
          <button onClick={() => router.push('/investigations')} className="hidden sm:inline-flex items-center gap-2 text-sm text-accent-cyan hover:text-text-primary transition-colors mb-6">
            View all <ArrowUpRight className="w-4 h-4" />
          </button>
        </div>
        <div className="mt-4">
          <InvestigationTable
            investigations={data?.investigations || []}
            isLoading={isLoading}
            onRowClick={(id) => router.push(`/investigations/${id}/overview`)}
          />
        </div>
      </div>
    </AppShell>
  );
};

export default Dashboard;