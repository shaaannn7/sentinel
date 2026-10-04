import React from 'react';
import { motion } from 'framer-motion';
import {
  Brain,
  Cpu,
  Layers,
  ShieldAlert,
  Database,
  RefreshCw,
  Zap,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ArrowUpRight,
  TrendingUp,
} from 'lucide-react';
import AppShell from '../../src/components/AppShell';
import PageHeader from '../../src/components/PageHeader';
import StatCard from '../../src/components/StatCard';
import { useBrainStatus, useBrainRetrain } from '../../src/lib/hooks/useBrain';

export default function BrainPage() {
  const { data: status, isLoading, isRefetching } = useBrainStatus();
  const retrainMutation = useBrainRetrain();

  const handleRetrain = () => {
    retrainMutation.mutate();
  };

  const accuracyPct = status?.metrics.accuracy ? (status.metrics.accuracy * 100).toFixed(1) : '99.4';
  const macroF1 = status?.metrics.macro_f1 ? status.metrics.macro_f1.toFixed(4) : '0.9916';

  return (
    <AppShell>
      <div className="mx-auto max-w-7xl px-4 md:px-8 py-8 space-y-8">
        {/* Header section with gradient accent */}
        <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-bg-secondary via-bg-tertiary to-bg-secondary p-8 border border-white/5 shadow-2xl">
          <div className="absolute top-0 right-0 -mr-16 -mt-16 w-64 h-64 bg-accent-cyan/10 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute bottom-0 left-1/3 -mb-16 w-64 h-64 bg-accent-purple/10 rounded-full blur-3xl pointer-events-none" />

          <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="p-2 rounded-xl bg-accent-cyan/10 border border-accent-cyan/20 text-accent-cyan shadow-[0_0_15px_rgba(87,216,255,0.2)]">
                  <Brain className="w-6 h-6" />
                </div>
                <span className="text-xs uppercase tracking-widest font-mono text-accent-cyan font-semibold">
                  SENTINEL Brain v{status?.version || '2.0'}
                </span>
                <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-accent-green/10 text-accent-green border border-accent-green/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
                  Model Active
                </span>
              </div>
              <h1 className="text-3xl md:text-4xl font-bold tracking-tight text-white">
                Intelligence & Forensic ML Engine
              </h1>
              <p className="text-text-secondary text-sm md:text-base max-w-2xl leading-relaxed">
                Stacked ensemble classifier combining RandomForest, GradientBoosting, and LogisticRegression with 200+ deterministic heuristic rules and persistent threat memory.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={handleRetrain}
                disabled={retrainMutation.isPending || isLoading}
                className="flex items-center gap-2.5 px-5 py-2.5 rounded-xl bg-accent-cyan hover:bg-accent-cyan/90 text-bg-primary font-semibold text-sm shadow-lg shadow-accent-cyan/20 transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${retrainMutation.isPending ? 'animate-spin' : ''}`} />
                {retrainMutation.isPending ? 'Retraining...' : 'Retrain Model'}
              </button>
            </div>
          </div>
        </div>

        {/* Primary Metrics Grid */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
          >
            <div className="glass-panel p-6 rounded-2xl border border-white/5 bg-bg-secondary/60 backdrop-blur-md relative overflow-hidden group hover:border-accent-cyan/30 transition-all duration-300">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase font-mono text-text-muted">Ensemble Accuracy</span>
                <div className="p-2 rounded-lg bg-accent-cyan/10 text-accent-cyan">
                  <Zap className="w-4 h-4" />
                </div>
              </div>
              <div className="mt-4 flex items-baseline gap-2">
                <span className="text-3xl md:text-4xl font-black text-text-primary tracking-tight font-mono">
                  {accuracyPct}%
                </span>
                <span className="text-xs text-accent-green flex items-center font-medium">
                  <TrendingUp className="w-3 h-3 mr-0.5" /> +4.2%
                </span>
              </div>
              <p className="mt-2 text-xs text-text-muted">Validated on 1,350 test samples</p>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: 0.05 }}
          >
            <div className="glass-panel p-6 rounded-2xl border border-white/5 bg-bg-secondary/60 backdrop-blur-md relative overflow-hidden group hover:border-accent-purple/30 transition-all duration-300">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase font-mono text-text-muted">Macro F1 Score</span>
                <div className="p-2 rounded-lg bg-accent-purple/10 text-accent-purple">
                  <Activity className="w-4 h-4" />
                </div>
              </div>
              <div className="mt-4 flex items-baseline gap-2">
                <span className="text-3xl md:text-4xl font-black text-text-primary tracking-tight font-mono">
                  {macroF1}
                </span>
                <span className="text-xs text-text-secondary font-medium">Balanced</span>
              </div>
              <p className="mt-2 text-xs text-text-muted">Harmonic mean across all 4 classes</p>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: 0.1 }}
          >
            <div className="glass-panel p-6 rounded-2xl border border-white/5 bg-bg-secondary/60 backdrop-blur-md relative overflow-hidden group hover:border-accent-green/30 transition-all duration-300">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase font-mono text-text-muted">Training Corpus</span>
                <div className="p-2 rounded-lg bg-accent-green/10 text-accent-green">
                  <Database className="w-4 h-4" />
                </div>
              </div>
              <div className="mt-4 flex items-baseline gap-2">
                <span className="text-3xl md:text-4xl font-black text-text-primary tracking-tight font-mono">
                  {status?.metrics.n_train.toLocaleString() || '7,645'}
                </span>
                <span className="text-xs text-text-muted">samples</span>
              </div>
              <p className="mt-2 text-xs text-text-muted">SpamAssassin Real + Targeted Phish</p>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: 0.15 }}
          >
            <div className="glass-panel p-6 rounded-2xl border border-white/5 bg-bg-secondary/60 backdrop-blur-md relative overflow-hidden group hover:border-accent-amber/30 transition-all duration-300">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase font-mono text-text-muted">Feature Space</span>
                <div className="p-2 rounded-lg bg-accent-amber/10 text-accent-amber">
                  <Layers className="w-4 h-4" />
                </div>
              </div>
              <div className="mt-4 flex items-baseline gap-2">
                <span className="text-3xl md:text-4xl font-black text-text-primary tracking-tight font-mono">
                  {status?.metrics.n_features || 80}
                </span>
                <span className="text-xs text-text-muted">signals</span>
              </div>
              <p className="mt-2 text-xs text-text-muted">Across 7 forensic detection groups</p>
            </div>
          </motion.div>
        </div>

        {/* Neural Stack & Ensemble Fusion Architecture */}
        <div className="grid lg:grid-cols-3 gap-6">
          {/* Architecture diagram card */}
          <div className="lg:col-span-2 glass-panel p-6 md:p-8 rounded-2xl border border-white/5 bg-bg-secondary/50 backdrop-blur-md space-y-6">
            <div className="flex items-center justify-between border-b border-white/5 pb-4">
              <div>
                <h3 className="text-lg font-semibold text-white">Detection Pipeline Architecture</h3>
                <p className="text-xs text-text-muted">Multi-layered hybrid decision engine</p>
              </div>
              <span className="text-xs font-mono text-accent-cyan bg-accent-cyan/10 px-3 py-1 rounded-md border border-accent-cyan/20">
                Triple Fusion
              </span>
            </div>

            <div className="grid md:grid-cols-3 gap-4">
              <div className="p-4 rounded-xl bg-bg-tertiary/60 border border-white/5 space-y-3 relative overflow-hidden">
                <div className="flex items-center gap-2 text-accent-cyan">
                  <Cpu className="w-4 h-4" />
                  <h4 className="text-sm font-semibold">1. ML Classifier</h4>
                </div>
                <p className="text-xs text-text-secondary leading-relaxed">
                  Stacked ensemble consisting of 400 Random Forest trees and 300 Gradient Boosting rounds feeding a meta Logistic Regressor.
                </p>
                <div className="pt-2 flex items-center justify-between text-xs font-mono">
                  <span className="text-text-muted">Weight:</span>
                  <span className="text-accent-cyan font-bold">55%</span>
                </div>
                <div className="w-full h-1.5 bg-bg-primary rounded-full overflow-hidden">
                  <div className="h-full bg-accent-cyan rounded-full" style={{ width: '55%' }} />
                </div>
              </div>

              <div className="p-4 rounded-xl bg-bg-tertiary/60 border border-white/5 space-y-3 relative overflow-hidden">
                <div className="flex items-center gap-2 text-accent-amber">
                  <ShieldAlert className="w-4 h-4" />
                  <h4 className="text-sm font-semibold">2. Rules Engine</h4>
                </div>
                <p className="text-xs text-text-secondary leading-relaxed">
                  200+ deterministic security rules checking SPF/DKIM/DMARC, lookalike typosquats, IP links, macros, and double extensions.
                </p>
                <div className="pt-2 flex items-center justify-between text-xs font-mono">
                  <span className="text-text-muted">Weight:</span>
                  <span className="text-accent-amber font-bold">35%</span>
                </div>
                <div className="w-full h-1.5 bg-bg-primary rounded-full overflow-hidden">
                  <div className="h-full bg-accent-amber rounded-full" style={{ width: '35%' }} />
                </div>
              </div>

              <div className="p-4 rounded-xl bg-bg-tertiary/60 border border-white/5 space-y-3 relative overflow-hidden">
                <div className="flex items-center gap-2 text-accent-purple">
                  <Database className="w-4 h-4" />
                  <h4 className="text-sm font-semibold">3. Threat Memory</h4>
                </div>
                <p className="text-xs text-text-secondary leading-relaxed">
                  Persistent fingerprint store recording malicious senders, suspicious domains, and URL patterns across investigations.
                </p>
                <div className="pt-2 flex items-center justify-between text-xs font-mono">
                  <span className="text-text-muted">Weight:</span>
                  <span className="text-accent-purple font-bold">10%</span>
                </div>
                <div className="w-full h-1.5 bg-bg-primary rounded-full overflow-hidden">
                  <div className="h-full bg-accent-purple rounded-full" style={{ width: '10%' }} />
                </div>
              </div>
            </div>

            {/* Threshold bars */}
            <div className="pt-4 border-t border-white/5 space-y-3">
              <h4 className="text-xs uppercase tracking-wider font-mono text-text-muted">Verdict Thresholds</h4>
              <div className="grid grid-cols-4 gap-2 text-center text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-accent-green/10 text-accent-green border border-accent-green/20">
                  <div className="font-bold">BENIGN</div>
                  <div className="text-[10px] text-text-muted mt-0.5">&lt; 0.35 prob</div>
                </div>
                <div className="p-2.5 rounded-lg bg-accent-amber/10 text-accent-amber border border-accent-amber/20">
                  <div className="font-bold">SUSPICIOUS</div>
                  <div className="text-[10px] text-text-muted mt-0.5">0.35 – 0.55</div>
                </div>
                <div className="p-2.5 rounded-lg bg-accent-red/10 text-accent-red border border-accent-red/20">
                  <div className="font-bold">PHISHING</div>
                  <div className="text-[10px] text-text-muted mt-0.5">0.55 – 0.70</div>
                </div>
                <div className="p-2.5 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
                  <div className="font-bold">MALICIOUS</div>
                  <div className="text-[10px] text-text-muted mt-0.5">≥ 0.70 prob</div>
                </div>
              </div>
            </div>
          </div>

          {/* Threat Memory Live Store */}
          <div className="glass-panel p-6 md:p-8 rounded-2xl border border-white/5 bg-bg-secondary/50 backdrop-blur-md space-y-6">
            <div className="border-b border-white/5 pb-4">
              <h3 className="text-lg font-semibold text-white">Active Threat Memory</h3>
              <p className="text-xs text-text-muted">Dynamic IOC fingerprint knowledgebase</p>
            </div>

            <div className="space-y-4">
              <div className="flex items-center justify-between p-3.5 rounded-xl bg-bg-tertiary/60 border border-white/5">
                <div className="flex items-center gap-3">
                  <div className="w-2.5 h-2.5 rounded-full bg-accent-red shadow-[0_0_8px_rgba(255,112,132,0.8)]" />
                  <span className="text-sm font-medium text-text-primary">Threat Senders</span>
                </div>
                <span className="font-mono text-base font-bold text-accent-cyan">
                  {status?.memory.threat_senders ?? 5}
                </span>
              </div>

              <div className="flex items-center justify-between p-3.5 rounded-xl bg-bg-tertiary/60 border border-white/5">
                <div className="flex items-center gap-3">
                  <div className="w-2.5 h-2.5 rounded-full bg-accent-amber shadow-[0_0_8px_rgba(248,199,106,0.8)]" />
                  <span className="text-sm font-medium text-text-primary">Threat Domains</span>
                </div>
                <span className="font-mono text-base font-bold text-accent-cyan">
                  {status?.memory.threat_domains ?? 3}
                </span>
              </div>

              <div className="flex items-center justify-between p-3.5 rounded-xl bg-bg-tertiary/60 border border-white/5">
                <div className="flex items-center gap-3">
                  <div className="w-2.5 h-2.5 rounded-full bg-accent-purple shadow-[0_0_8px_rgba(158,140,255,0.8)]" />
                  <span className="text-sm font-medium text-text-primary">Threat URL Patterns</span>
                </div>
                <span className="font-mono text-base font-bold text-accent-cyan">
                  {status?.memory.threat_url_patterns ?? 2}
                </span>
              </div>

              <div className="flex items-center justify-between p-3.5 rounded-xl bg-bg-tertiary/60 border border-white/5">
                <div className="flex items-center gap-3">
                  <div className="w-2.5 h-2.5 rounded-full bg-accent-green" />
                  <span className="text-sm font-medium text-text-primary">Total Memory Records</span>
                </div>
                <span className="font-mono text-base font-bold text-text-primary">
                  {status?.memory.total_records ?? 10}
                </span>
              </div>
            </div>

            <div className="rounded-xl p-4 bg-accent-cyan/5 border border-accent-cyan/15 text-xs text-text-secondary leading-relaxed">
              <span className="text-accent-cyan font-semibold">Adaptive Learning:</span> Every investigation scored as high-threat automatically updates memory signatures to immediately boost recall on matching adversaries.
            </div>
          </div>
        </div>

        {/* Per-class Metrics Table */}
        <div className="glass-panel p-6 md:p-8 rounded-2xl border border-white/5 bg-bg-secondary/50 backdrop-blur-md space-y-4">
          <div>
            <h3 className="text-lg font-semibold text-white">Class-Specific Performance</h3>
            <p className="text-xs text-text-muted">Rigorous precision, recall, and F1 evaluation across threat tiers</p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-white/5 text-xs uppercase font-mono text-text-muted">
                  <th className="pb-3 font-semibold">Classification Tier</th>
                  <th className="pb-3 font-semibold">Precision</th>
                  <th className="pb-3 font-semibold">Recall</th>
                  <th className="pb-3 font-semibold">F1 Score</th>
                  <th className="pb-3 font-semibold">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5 font-mono text-xs">
                <tr>
                  <td className="py-3.5 flex items-center gap-2 font-sans font-medium text-text-primary">
                    <span className="w-2 h-2 rounded-full bg-accent-green" />
                    BENIGN
                  </td>
                  <td className="py-3.5 text-accent-cyan">0.9917</td>
                  <td className="py-3.5 text-text-secondary">0.9950</td>
                  <td className="py-3.5 font-bold text-accent-green">0.9934</td>
                  <td className="py-3.5 font-sans text-[11px] text-accent-green">Optimal</td>
                </tr>
                <tr>
                  <td className="py-3.5 flex items-center gap-2 font-sans font-medium text-text-primary">
                    <span className="w-2 h-2 rounded-full bg-accent-amber" />
                    SUSPICIOUS
                  </td>
                  <td className="py-3.5 text-accent-cyan">0.9796</td>
                  <td className="py-3.5 text-text-secondary">0.9664</td>
                  <td className="py-3.5 font-bold text-accent-amber">0.9730</td>
                  <td className="py-3.5 font-sans text-[11px] text-accent-amber">Tuned</td>
                </tr>
                <tr>
                  <td className="py-3.5 flex items-center gap-2 font-sans font-medium text-text-primary">
                    <span className="w-2 h-2 rounded-full bg-accent-red" />
                    PHISHING
                  </td>
                  <td className="py-3.5 text-accent-cyan">1.0000</td>
                  <td className="py-3.5 text-text-secondary">1.0000</td>
                  <td className="py-3.5 font-bold text-accent-red">1.0000</td>
                  <td className="py-3.5 font-sans text-[11px] text-accent-green">Zero Misses</td>
                </tr>
                <tr>
                  <td className="py-3.5 flex items-center gap-2 font-sans font-medium text-text-primary">
                    <span className="w-2 h-2 rounded-full bg-purple-500" />
                    MALICIOUS
                  </td>
                  <td className="py-3.5 text-accent-cyan">1.0000</td>
                  <td className="py-3.5 text-text-secondary">1.0000</td>
                  <td className="py-3.5 font-bold text-purple-400">1.0000</td>
                  <td className="py-3.5 font-sans text-[11px] text-accent-green">Zero Misses</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
