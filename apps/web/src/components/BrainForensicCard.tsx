import React from 'react';
import { motion } from 'framer-motion';
import { Brain, Cpu, ShieldAlert, AlertTriangle, CheckCircle, Info, Sparkles, TrendingUp, TrendingDown } from 'lucide-react';
import { useBrainExplain } from '../lib/hooks/useBrain';

interface BrainForensicCardProps {
  investigationId: string;
}

export const BrainForensicCard: React.FC<BrainForensicCardProps> = ({ investigationId }) => {
  const { data: explanation, isLoading, error } = useBrainExplain(investigationId);

  if (isLoading) {
    return (
      <div className="p-6 rounded-2xl border border-white/5 bg-bg-secondary/40 backdrop-blur-md animate-pulse space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-accent-cyan/10" />
          <div className="h-4 w-48 bg-white/10 rounded" />
        </div>
        <div className="h-16 w-full bg-white/5 rounded-xl" />
      </div>
    );
  }

  if (error || !explanation) {
    return null;
  }

  const verdictColor =
    explanation.verdict === 'MALICIOUS' ? 'text-purple-400 border-purple-500/20 bg-purple-500/10' :
    explanation.verdict === 'PHISHING' ? 'text-accent-red border-accent-red/20 bg-accent-red/10' :
    explanation.verdict === 'SUSPICIOUS' ? 'text-accent-amber border-accent-amber/20 bg-accent-amber/10' :
    'text-accent-green border-accent-green/20 bg-accent-green/10';

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="rounded-2xl border border-white/10 bg-gradient-to-b from-bg-secondary via-bg-tertiary/60 to-bg-secondary p-6 md:p-8 backdrop-blur-md shadow-2xl space-y-6 relative overflow-hidden"
    >
      <div className="absolute top-0 right-0 w-80 h-80 bg-accent-cyan/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/5 pb-5">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20 shadow-[0_0_15px_rgba(87,216,255,0.15)]">
            <Brain className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-bold text-white tracking-tight">Brain Forensic Analysis</h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20">
                Triple-Ensemble
              </span>
            </div>
            <p className="text-xs text-text-muted">ML Stack + Heuristic Rules + Threat Memory</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-xs text-text-muted font-mono">Ensemble Risk</div>
            <div className="text-xl font-bold font-mono text-white">
              {explanation.risk_score}<span className="text-xs text-text-muted">/100</span>
            </div>
          </div>
          <span className={`px-3 py-1 rounded-lg text-xs font-bold font-mono uppercase border ${verdictColor}`}>
            {explanation.verdict}
          </span>
        </div>
      </div>

      {/* Narrative */}
      {explanation.narrative && (
        <div className="p-4 rounded-xl bg-bg-primary/50 border border-white/5 text-xs text-text-secondary leading-relaxed flex items-start gap-3">
          <Sparkles className="w-4 h-4 text-accent-cyan flex-shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-text-primary block mb-0.5">Analyst Narrative</span>
            {explanation.narrative}
          </div>
        </div>
      )}

      {/* ML Probabilities & Top Rules Grid */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* ML Model Class Distribution */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-mono text-text-muted flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-accent-cyan" /> ML Model Probabilities
            </span>
            <span className="text-[11px] font-mono text-accent-cyan font-medium">
              Predicted: {explanation.ml_label} ({(explanation.ml_confidence * 100).toFixed(0)}%)
            </span>
          </div>
          <div className="space-y-2 p-3.5 rounded-xl bg-bg-primary/30 border border-white/5">
            {Object.entries(explanation.raw_proba || {})
              .sort(([, a], [, b]) => b - a)
              .map(([cls, prob]) => {
                const barColor =
                  cls === 'MALICIOUS' ? 'bg-purple-500' :
                  cls === 'PHISHING' ? 'bg-accent-red' :
                  cls === 'SUSPICIOUS' ? 'bg-accent-amber' :
                  'bg-accent-green';

                const pct = Math.round(prob * 100);
                return (
                  <div key={cls} className="space-y-1">
                    <div className="flex justify-between text-[11px] font-mono">
                      <span className="text-text-secondary">{cls}</span>
                      <span className="text-text-primary font-semibold">{pct}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${pct}%` }}
                        transition={{ duration: 0.5, ease: 'easeOut' }}
                        className={`h-full ${barColor} rounded-full`}
                      />
                    </div>
                  </div>
                );
              })}
          </div>
        </div>

        {/* Top Rule Signals */}
        <div className="space-y-3">
          <span className="text-xs uppercase font-mono text-text-muted flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-accent-amber" /> Triggered Heuristic Rules
          </span>
          <div className="space-y-2 p-3.5 rounded-xl bg-bg-primary/30 border border-white/5 max-h-[160px] overflow-y-auto">
            {explanation.top_rules.length === 0 ? (
              <p className="text-xs text-text-muted">No high-severity rules triggered.</p>
            ) : (
              explanation.top_rules.map((rule) => {
                const sevColor =
                  rule.severity === 'CRITICAL' ? 'text-accent-red bg-accent-red/10 border-accent-red/20' :
                  rule.severity === 'HIGH' ? 'text-accent-red bg-accent-red/10 border-accent-red/20' :
                  rule.severity === 'MEDIUM' ? 'text-accent-amber bg-accent-amber/10 border-accent-amber/20' :
                  'text-text-secondary bg-white/5 border-white/10';

                return (
                  <div key={rule.rule_id} className="flex items-start justify-between gap-2 p-2 rounded-lg bg-bg-tertiary/40 border border-white/5 text-xs">
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-accent-cyan text-[11px]">{rule.rule_id}</span>
                        <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono border ${sevColor}`}>
                          {rule.severity}
                        </span>
                      </div>
                      <p className="text-text-secondary text-[11px] line-clamp-1">{rule.description}</p>
                    </div>
                    <span className="font-mono text-accent-amber font-bold text-[11px] whitespace-nowrap">
                      +{rule.points} pts
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Top Feature Importances */}
      {explanation.top_features.length > 0 && (
        <div className="space-y-3 pt-2 border-t border-white/5">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-mono text-text-muted">Top Contributing Signals</span>
            <span className="text-[11px] text-text-muted">RandomForest feature weights</span>
          </div>
          <div className="grid sm:grid-cols-2 md:grid-cols-3 gap-2">
            {explanation.top_features.slice(0, 6).map((feat) => {
              const isRisk = feat.direction === 'increases_risk';
              const isSafe = feat.direction === 'decreases_risk';
              return (
                <div key={feat.name} className="p-2.5 rounded-xl bg-bg-primary/40 border border-white/5 space-y-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-text-primary font-medium truncate max-w-[140px]" title={feat.description}>
                      {feat.description}
                    </span>
                    {isRisk && (
                      <span className="flex items-center text-accent-red font-mono text-[10px]">
                        <TrendingUp className="w-3 h-3 mr-0.5" /> +risk
                      </span>
                    )}
                    {isSafe && (
                      <span className="flex items-center text-accent-green font-mono text-[10px]">
                        <TrendingDown className="w-3 h-3 mr-0.5" /> -risk
                      </span>
                    )}
                  </div>
                  <div className="flex items-center justify-between text-[10px] font-mono text-text-muted">
                    <span>Val: {feat.value}</span>
                    <span>Imp: {(feat.importance * 100).toFixed(1)}%</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </motion.div>
  );
};
