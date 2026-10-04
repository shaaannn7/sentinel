import { useRouter } from 'next/router';
import Link from 'next/link';
import { useInvestigation } from '../../../src/lib/hooks/useInvestigation';
import AppShell from '../../../src/components/AppShell';
import PageHeader from '../../../src/components/PageHeader';
import StatCard from '../../../src/components/StatCard';
import StatusBadge from '../../../src/components/StatusBadge';
import SeverityBadge from '../../../src/components/SeverityBadge';
import InvestigationTable from '../../../src/components/InvestigationTable';
import { BrainForensicCard } from '../../../src/components/BrainForensicCard';
import { ThreatRelationshipGraph } from '../../../src/components/ThreatRelationshipGraph';
import { AlertCircle, RefreshCw, Loader, FileText, MapPin, Code, BarChart2, TrendingUp, Clock, Shield } from 'lucide-react';

export default function TabPage() {
  const router = useRouter();
  const id = typeof router.query.id === 'string' ? router.query.id : undefined;
  const tab = typeof router.query.tab === 'string' ? router.query.tab : 'overview';
  const { data: investigation, isLoading, error } = useInvestigation(id);

  if (isLoading) {
    return (
      <AppShell>
        <div className="flex items-center justify-center min-h-[400px]">
          <Loader className="w-8 h-8 text-accent-cyan animate-spin" />
        </div>
      </AppShell>
    );
  }

  if (error) {
    return (
      <AppShell>
        <div className="p-6 text-center text-accent-red">
          <AlertCircle className="w-6 h-6 mb-3" />
          <p>Failed to load investigation: {error.message}</p>
        </div>
      </AppShell>
    );
  }

  if (!investigation) {
    return (
      <AppShell>
        <div className="p-6 text-center text-text-muted">
          <p>Investigation not found</p>
        </div>
      </AppShell>
    );
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: FileText },
    { id: 'email', label: 'Email', icon: Code },
    { id: 'authentication', label: 'Authentication', icon: Shield },
    { id: 'indicators', label: 'Indicators', icon: TrendingUp },
    { id: 'graph', label: 'Graph', icon: MapPin },
    { id: 'timeline', label: 'Timeline', icon: Clock },
    { id: 'report', label: 'Report', icon: BarChart2 },
  ];

  const currentTab = tabs.find(t => t.id === tab) || tabs[0];

  return (
    <AppShell>
      <div className="container mx-auto px-4 py-8">
        <PageHeader
          title={investigation.subject || `Investigation ${investigation.externalId}`}
          description={`${investigation.status} • ${investigation.verdict}`}
        />          <nav className="mb-6 border-b border-border-default">
          <ul className="flex gap-4">
            {tabs.map(t => (
              <li key={t.id}>
                <Link
                  href={`/investigations/${investigation.id}/${t.id}`}
                  className={`flex items-center gap-2 px-3 py-2 text-sm font-medium rounded transition-colors ${
                    t.id === currentTab.id
                      ? 'bg-bg-tertiary text-text-primary'
                      : 'text-text-secondary hover:bg-bg-tertiary hover:text-text-primary'
                  }`}
                >
                  {t.icon && <t.icon className="w-4 h-4" />}
                  <span className="ml-2">{t.label}</span>
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        <div className="rounded-lg border border-border-default bg-bg-secondary p-6">
          {currentTab.id === 'overview' && (
            <OverviewTab investigation={investigation} />
          )}
          {currentTab.id === 'email' && (
            <EmailTab artifact={investigation.artifact} />
          )}
          {currentTab.id === 'authentication' && (
            <AuthenticationTab authResults={investigation.artifact?.authResults} />
          )}
          {currentTab.id === 'indicators' && (
            <IndicatorsTab indicators={investigation.artifact?.indicators} />
          )}
          {currentTab.id === 'graph' && (
            <ThreatRelationshipGraph investigation={investigation as any} />
          )}
          {currentTab.id === 'timeline' && (
            <TimelineTab receivedHops={investigation.artifact?.receivedHops} />
          )}
          {currentTab.id === 'report' && (
            <ReportTab investigation={investigation} />
          )}
        </div>
      </div>
    </AppShell>
  );
}

interface OverviewTabProps {
  investigation: {
    id: string;
    externalId: string;
    subject: string;
    verdict: 'benign' | 'suspicious' | 'malicious' | 'unknown';
    riskScore: number;
    confidence: number;
    status: 'pending' | 'processing' | 'completed' | 'failed';
    summary: string;
    createdAt: string;
    artifact: {
      indicators: Array<{ id: string; type: string; value: string; confidence: number }>;
      attachments: Array<{ id: string; filename: string; size: number; isSuspicious: boolean }>;
    };
  };
}

function OverviewTab({ investigation }: OverviewTabProps) {
  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <StatCard
          label="Threat Score"
          value={investigation.riskScore}
          change={`/${100}`}
          changeType="neutral"
        >
          <SeverityBadge
            label={investigation.riskScore >= 80 ? 'Critical' : investigation.riskScore >= 60 ? 'High' : investigation.riskScore >= 30 ? 'Medium' : 'Low'}
            severity={
              investigation.riskScore >= 80 ? 'critical' :
              investigation.riskScore >= 60 ? 'high' :
              investigation.riskScore >= 30 ? 'medium' : 'low'
            }
          />
        </StatCard>
        <StatCard
          label="Confidence"
          value={`${Math.round(investigation.confidence)}%`}
          changeType="neutral"
        >
          <StatusBadge label={investigation.confidence >= 80 ? 'High' : investigation.confidence >= 60 ? 'Medium' : 'Low'} type="processing" />
        </StatCard>
        <StatCard
          label="Evidence Count"
          value={(investigation.artifact?.indicators?.length || 0) + (investigation.artifact?.attachments?.length || 0)}
          changeType="neutral"
        >
          <StatusBadge label="Complete" type="completed" />
        </StatCard>
      </div>

      <BrainForensicCard investigationId={investigation.id} />

      <div className="space-y-4">
        <h2 className="text-lg font-medium text-text-primary">Summary</h2>
        <p className="text-text-secondary">{investigation.summary}</p>
      </div>

      <div>
        <h2 className="text-lg font-medium text-text-primary">Key Indicators</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="text-xs uppercase text-text-muted">
                <th className="p-2">Type</th>
                <th className="p-2">Value</th>
                <th className="p-2">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {investigation.artifact.indicators.slice(0, 10).map((indicator) => (
                <tr key={indicator.id} className="border-t border-border-default">
                  <td className="p-2 text-text-secondary">{indicator.type}</td>
                  <td className="p-2 break-all font-mono text-text-primary">{indicator.value}</td>
                  <td className="p-2">
                    <SeverityBadge
                      label={`${Math.round(indicator.confidence * 100)}%`}
                      severity={
                        indicator.confidence >= 0.8 ? 'high' :
                        indicator.confidence >= 0.6 ? 'medium' : 'low'
                      }
                      size="sm"
                      showDot={false}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div>
        <h2 className="text-lg font-medium text-text-primary">Attachments</h2>
        {investigation.artifact.attachments.length === 0 ? (
          <p className="text-text-secondary">No attachments found</p>
        ) : (
          <div className="space-y-2">
            {investigation.artifact.attachments.map((attachment) => (
              <div key={attachment.id} className="flex items-center gap-3 p-3 bg-bg-tertiary rounded">
                <div className="flex-shrink-0 w-10 h-10 rounded bg-accent-cyan/10 flex items-center justify-center text-accent-cyan">
                  {attachment.isSuspicious ? (
                    <AlertCircle className="w-5 h-5" />
                  ) : (
                    <FileText className="w-5 h-5" />
                  )}
                </div>
                <div>
                  <p className="font-mono text-text-primary">{attachment.filename}</p>
                  <p className="text-text-tertiary text-xs">
                    {`${(attachment.size / 1024).toFixed(1)} KB • ${attachment.isSuspicious ? 'Suspicious' : 'Safe'}`}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

interface EmailTabProps {
  artifact: {
    messageId: string;
    subject: string;
    from: string;
    to: string[];
    cc: string[];
    date: string;
    textBody?: string;
    htmlBody?: string;
    headers: Array<{ name: string; value: string }>;
  };
}

function EmailTab({ artifact }: EmailTabProps) {
  return (
    <div className="space-y-6">
      <div className="space-y-4">
        <h2 className="text-lg font-medium text-text-primary">Header Information</h2>
        <div className="space-y-2">
          <div className="grid gap-2 md:grid-cols-2">
            <div>
              <p className="text-text-tertiary text-xs">From</p>
              <p className="font-mono text-text-primary">{artifact.from}</p>
            </div>
            <div>
              <p className="text-text-tertiary text-xs">To</p>
              <p className="font-mono text-text-primary">{artifact.to.join(', ')}</p>
            </div>
            <div>
              <p className="text-text-tertiary text-xs">CC</p>
              <p className="font-mono text-text-primary">{artifact.cc.join(', ') || '(none)'}</p>
            </div>
            <div>
              <p className="text-text-tertiary text-xs">Date</p>
              <p className="font-mono text-text-primary">
                {new Date(artifact.date).toLocaleString()}
              </p>
            </div>
            <div>
              <p className="text-text-tertiary text-xs">Subject</p>
              <p className="text-text-primary">{artifact.subject}</p>
            </div>
            <div>
              <p className="text-text-tertiary text-xs">Message ID</p>
              <p className="font-mono text-text-secondary">{artifact.messageId}</p>
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        <h2 className="text-lg font-medium text-text-primary">Email Headers</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="text-xs uppercase text-text-muted">
                <th className="p-2">Header</th>
                <th className="p-2">Value</th>
              </tr>
            </thead>
            <tbody>
              {artifact.headers.map((header) => (
                <tr key={`${header.name}-${header.value}`} className="border-t border-border-default">
                  <td className="p-2 font-mono text-text-secondary">{header.name}</td>
                  <td className="p-2 break-all font-mono text-text-primary">{header.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="space-y-4">
        <h2 className="text-lg font-medium text-text-primary">Email Body</h2>
        {artifact.textBody ? (
          <div className="bg-bg-tertiary rounded p-4 font-mono text-text-secondary">
            <pre className="whitespace-pre-wrap">{artifact.textBody}</pre>
          </div>
        ) : artifact.htmlBody ? (
          <div className="bg-bg-tertiary rounded p-4">
            <div dangerouslySetInnerHTML={{ __html: artifact.htmlBody }} />
          </div>
        ) : (
          <p className="text-text-secondary">No body content available</p>
        )}
      </div>
    </div>
  );
}

interface AuthenticationTabProps {
  authResults: Array<{
    domain: string;
    spf: { result: string; details: string };
    dkim: { result: string; details: string };
    dmarc: { result: string; details: string };
    overall: 'pass' | 'fail' | 'none';
  }>;
}

function AuthenticationTab({ authResults }: AuthenticationTabProps) {
  return (
    <div className="space-y-6">
      {authResults.length === 0 ? (
        <p className="text-text-secondary">No authentication results found</p>
      ) : (
        <>
          <h2 className="text-lg font-medium text-text-primary">Authentication Results</h2>
          <div className="space-y-4">
            {authResults.map((result) => (
              <div key={result.domain} className="border border-border-default rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-medium text-text-primary">{result.domain}</h3>
                  <div className="flex items-center gap-2">
                    <StatusBadge
                      label={result.overall.toUpperCase()}
                      type={
                        result.overall === 'pass' ? 'completed' :
                        result.overall === 'fail' ? 'failed' : 'pending'
                      }
                    />
                  </div>
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-text-tertiary">SPF:</span>
                    <span className="font-mono">{result.spf.result}</span>
                    <span className="text-text-secondary">{result.spf.details}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-text-tertiary">DKIM:</span>
                    <span className="font-mono">{result.dkim.result}</span>
                    <span className="text-text-secondary">{result.dkim.details}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-text-tertiary">DMARC:</span>
                    <span className="font-mono">{result.dmarc.result}</span>
                    <span className="text-text-secondary">{result.dmarc.details}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

interface IndicatorsTabProps {
  indicators: Array<{
    id: string;
    type: string;
    value: string;
    confidence: number;
    tags: string[];
    source: string;
    threatIntel?: {
      source: string;
      malicious: boolean;
      categories: string[];
      confidence: number;
    };
  }>;
}

function IndicatorsTab({ indicators }: IndicatorsTabProps) {
  return (
    <div className="space-y-6">
      {indicators.length === 0 ? (
        <p className="text-text-secondary">No indicators found</p>
      ) : (
        <>
          <h2 className="text-lg font-medium text-text-primary">Extracted Indicators</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-xs uppercase text-text-muted">
                  <th className="p-2">Type</th>
                  <th className="p-2">Value</th>
                  <th className="p-2">Source</th>
                  <th className="p-2">Confidence</th>
                  <th className="p-2">Tags</th>
                </tr>
              </thead>
              <tbody>
                {indicators.map((indicator) => (
                  <tr key={indicator.id} className="border-t border-border-default">
                    <td className="p-2 text-text-secondary">{indicator.type}</td>
                    <td className="p-2 break-all font-mono text-text-primary">{indicator.value}</td>
                    <td className="p-2 text-text-secondary">{indicator.source}</td>
                    <td className="p-2">
                      <SeverityBadge
                        label={`${Math.round(indicator.confidence * 100)}%`}
                        severity={
                          indicator.confidence >= 0.8 ? 'high' :
                          indicator.confidence >= 0.6 ? 'medium' : 'low'
                        }
                        size="sm"
                        showDot={false}
                      />
                    </td>
                    <td className="p-2">
                      {indicator.tags.map((tag) => (
                        <span key={tag} className="inline-flex items-center px-2 py-0.5 text-xs rounded-full bg-accent-cyan/10 text-accent-cyan">
                          #{tag}
                        </span>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="mt-6">
            <h2 className="text-lg font-medium text-text-primary">Threat Intelligence Matches</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="text-xs uppercase text-text-muted">
                    <th className="p-2">Indicator</th>
                    <th className="p-2">Source</th>
                    <th className="p-2">Malicious</th>
                    <th className="p-2">Categories</th>
                    <th className="p-2">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {indicators
                    .filter((i) => i.threatIntel)
                    .map((indicator) => (
                      <tr key={indicator.id} className="border-t border-border-default">
                        <td className="p-2 break-all font-mono text-text-secondary">{indicator.value}</td>
                        <td className="p-2 text-text-secondary">{indicator.threatIntel?.source}</td>
                        <td className="p-2">
                          <StatusBadge
                            label={indicator.threatIntel?.malicious ? 'MALICIOUS' : 'BENIGN'}
                            type={indicator.threatIntel?.malicious ? 'failed' : 'completed'}
                          />
                        </td>
                        <td className="p-2 text-text-secondary">
                          {indicator.threatIntel?.categories.join(', ') || '(none)'}
                        </td>
                        <td className="p-2">
                          <SeverityBadge
                            label={`${Math.round((indicator.threatIntel?.confidence ?? 0) * 100)}%`}
                            severity={
                              (indicator.threatIntel?.confidence ?? 0) >= 0.8 ? 'high' :
                              (indicator.threatIntel?.confidence ?? 0) >= 0.6 ? 'medium' : 'low'
                            }
                            size="sm"
                            showDot={false}
                          />
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

interface TimelineTabProps {
  receivedHops: Array<{
    index: number;
    from: string;
    by: string;
    via: string;
    with: string;
    id: string;
    for: string;
    timestamp: string;
    delayMs?: number;
    geo?: {
      country: string;
      countryCode: string;
      city: string;
      latitude: number;
      longitude: number;
      isp: string;
      org: string;
    };
    asn?: {
      number: number;
      name: string;
      route: string;
      domain: string;
      type: string;
    };
  }>;
}

function TimelineTab({ receivedHops }: TimelineTabProps) {
  return (
    <div className="space-y-6">
      {receivedHops.length === 0 ? (
        <p className="text-text-secondary">No received headers found</p>
      ) : (
        <>
          <h2 className="text-lg font-medium text-text-primary">Email Delivery Path</h2>
          <div className="space-y-4">
            {receivedHops.map((hop) => (
              <div key={hop.index} className="border-l-2 border-accent-cyan pl-4 mb-4">
                <div className="flex items-center gap-3 mb-2">
                  <span className="w-20 text-text-tertiary font-mono">Hop {hop.index}</span>
                  <span className="font-mono text-text-primary">{hop.by}</span>
                  {hop.geo && (
                    <>
                      <span className="ml-2 text-text-secondary">({hop.geo.city}, {hop.geo.countryCode})</span>
                      <span className="ml-2 text-text-tertiary">•</span>
                      <span className="text-text-secondary">{hop.geo.isp}</span>
                    </>
                  )}
                </div>
                <div className="space-y-1 text-sm">
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-text-tertiary">From:</span>
                    <span className="break-all text-text-secondary">{hop.from}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-text-tertiary">By:</span>
                    <span className="text-text-secondary">{hop.by}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-text-tertiary">Via:</span>
                    <span className="text-text-secondary">{hop.via}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-text-tertiary">With:</span>
                    <span className="text-text-secondary">{hop.with}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-text-tertiary">For:</span>
                    <span className="break-all text-text-secondary">{hop.for}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-text-tertiary">ID:</span>
                    <span className="font-mono text-text-secondary">{hop.id}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-text-tertiary">Timestamp:</span>
                    <span className="text-text-secondary">
                      {new Date(hop.timestamp).toLocaleString()}
                    </span>
                  </div>
                  {hop.delayMs && (
                    <div className="flex items-center gap-3">
                      <span className="w-20 text-text-tertiary">Delay:</span>
                      <span className="text-text-secondary">{hop.delayMs}ms</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

interface ReportTabProps {
  investigation: {
    id: string;
    externalId: string;
    subject: string;
    verdict: 'benign' | 'suspicious' | 'malicious' | 'unknown';
    riskScore: number;
    confidence: number;
    status: 'pending' | 'processing' | 'completed' | 'failed';
    summary: string;
    createdAt: string;
  };
}

function ReportTab({ investigation }: ReportTabProps) {
  return (
    <div className="space-y-6">
      <div className="border border-border-default rounded-lg p-5 bg-bg-tertiary">
        <h2 className="text-lg font-medium text-text-primary mb-4">Investigation Report</h2>
        <div className="space-y-4">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-lg bg-accent-cyan/10 flex items-center justify-center text-accent-cyan">
              <BarChart2 className="w-6 h-6" />
            </div>
            <div>
              <h3 className="font-medium text-text-primary">Investigation {investigation.externalId}</h3>
              <p className="text-text-secondary">
                Generated {new Date(investigation.createdAt).toLocaleDateString()} at {new Date(investigation.createdAt).toLocaleTimeString()}
              </p>
            </div>
          </div>
          <div className="space-y-3">
            <div className="border-t border-border-default pt-4">
              <p className="font-medium text-text-primary">Executive Summary</p>
              <p className="text-text-secondary mt-1">{investigation.summary}</p>
            </div>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <p className="text-text-tertiary">Verdict</p>
              <p className="text-text-primary font-medium">
                <StatusBadge label={investigation.verdict} type={investigation.verdict as any} />
              </p>
            </div>
            <div>
              <p className="text-text-tertiary">Risk Score</p>
              <p className="text-text-primary font-mono text-2xl">{investigation.riskScore}/100</p>
            </div>
            <div>
              <p className="text-text-tertiary">Confidence</p>
              <p className="text-text-primary font-mono text-2xl">{Math.round(investigation.confidence)}%</p>
            </div>
            <div>
              <p className="text-text-tertiary">Status</p>
              <p className="text-text-primary font-medium">
                <StatusBadge label={investigation.status} type={investigation.status as any} />
              </p>
            </div>
          </div>
          <div className="border-t border-border-default pt-4">
            <p className="font-medium text-text-primary">Recommended Actions</p>
            <ul className="mt-2 space-y-1 list-disc list-inside text-text-secondary">
              {investigation.verdict === 'malicious' && (
                <>
                  <li>Block sender domain and IP addresses</li>
                  <li>Update email filtering rules</li>
                  <li>Monitor for similar attack patterns</li>
                </>
              )}
              {investigation.verdict === 'suspicious' && (
                <>
                  <li>Quarantine similar emails for review</li>
                  <li>Enhance monitoring of sender domain</li>
                  <li>Consider user awareness training</li>
                </>
              )}
              {investigation.verdict === 'benign' && (
                <>
                  <li>No action required</li>
                  <li>Consider logging for trend analysis</li>
                </>
              )}
              {investigation.verdict === 'unknown' && (
                <>
                  <li>Manual review recommended</li>
                  <li>Consider submitting to threat intelligence platforms</li>
                  <li>Monitor for additional evidence</li>
                </>
              )}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}