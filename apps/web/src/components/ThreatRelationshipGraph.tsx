import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Mail, Globe, Shield, AlertTriangle, FileText, CheckCircle2, XCircle, ArrowRight, ExternalLink } from 'lucide-react';

interface ThreatGraphProps {
  investigation: {
    id: string;
    externalId: string;
    subject: string;
    verdict: string;
    riskScore: number;
    sender: string;
    artifact?: {
      indicators?: Array<{ id: string; type: string; value: string; confidence: number }>;
      attachments?: Array<{ id: string; filename: string; size: number; isSuspicious: boolean }>;
      authResults?: Array<{ protocol: string; result: string; details?: any }>;
    };
  };
}

export const ThreatRelationshipGraph: React.FC<ThreatGraphProps> = ({ investigation }) => {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const sender = investigation.sender || 'unknown@sender';
  const senderDomain = sender.includes('@') ? sender.split('@')[1] : sender;
  const indicators = investigation.artifact?.indicators || [];
  const attachments = investigation.artifact?.attachments || [];
  const isHighRisk = investigation.riskScore >= 50;

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold text-white">Forensic Evidence & Entity Graph</h3>
          <p className="text-xs text-text-muted">Interactive entity relationship map linking sender, authentication, indicators, and verdict</p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="flex items-center gap-1.5 text-accent-green"><span className="w-2 h-2 rounded-full bg-accent-green" /> Authenticated</span>
          <span className="flex items-center gap-1.5 text-accent-red ml-2"><span className="w-2 h-2 rounded-full bg-accent-red" /> Threat Node</span>
        </div>
      </div>

      {/* SVG Canvas Map */}
      <div className="relative rounded-2xl border border-white/10 bg-gradient-to-b from-bg-primary via-bg-secondary/80 to-bg-primary p-6 md:p-10 overflow-hidden shadow-2xl">
        <div className="absolute inset-0 bg-[radial-gradient(#22304a_1px,transparent_1px)] [background-size:16px_16px] opacity-30 pointer-events-none" />

        <div className="relative z-10 grid md:grid-cols-4 gap-6 items-center">
          {/* Column 1: SENDER ENTITY */}
          <motion.div
            whileHover={{ scale: 1.02 }}
            className={`p-4 rounded-xl border transition-all cursor-pointer ${
              selectedNode === 'sender'
                ? 'border-accent-cyan bg-accent-cyan/10 shadow-[0_0_20px_rgba(87,216,255,0.2)]'
                : 'border-white/10 bg-bg-secondary/70 hover:border-white/20'
            }`}
            onClick={() => setSelectedNode('sender')}
          >
            <div className="flex items-center gap-2 text-accent-cyan mb-2">
              <Globe className="w-4 h-4" />
              <span className="text-xs font-mono font-bold uppercase">Sender Entity</span>
            </div>
            <div className="text-sm font-semibold text-text-primary truncate" title={sender}>
              {sender}
            </div>
            <div className="text-[11px] font-mono text-text-muted mt-1">Domain: {senderDomain}</div>
          </motion.div>

          {/* Column 2: MESSAGE ARTIFACT */}
          <motion.div
            whileHover={{ scale: 1.02 }}
            className={`p-4 rounded-xl border transition-all cursor-pointer ${
              selectedNode === 'artifact'
                ? 'border-accent-purple bg-accent-purple/10 shadow-[0_0_20px_rgba(158,140,255,0.2)]'
                : 'border-white/10 bg-bg-secondary/70 hover:border-white/20'
            }`}
            onClick={() => setSelectedNode('artifact')}
          >
            <div className="flex items-center gap-2 text-accent-purple mb-2">
              <Mail className="w-4 h-4" />
              <span className="text-xs font-mono font-bold uppercase">Email Artifact</span>
            </div>
            <div className="text-sm font-semibold text-text-primary truncate" title={investigation.subject}>
              {investigation.subject || 'No Subject'}
            </div>
            <div className="text-[11px] font-mono text-text-muted mt-1">
              Case ID: {investigation.externalId}
            </div>
          </motion.div>

          {/* Column 3: EXTRACTED EVIDENCE (URLs & Attachments) */}
          <div className="space-y-3">
            <motion.div
              whileHover={{ scale: 1.02 }}
              className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                selectedNode === 'indicators'
                  ? 'border-accent-amber bg-accent-amber/10 shadow-[0_0_20px_rgba(248,199,106,0.2)]'
                  : 'border-white/10 bg-bg-secondary/70 hover:border-white/20'
              }`}
              onClick={() => setSelectedNode('indicators')}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold uppercase text-accent-amber flex items-center gap-1.5">
                  <ExternalLink className="w-3.5 h-3.5" /> Indicators ({indicators.length})
                </span>
                <span className="text-[10px] font-mono text-text-muted">URLs & IPs</span>
              </div>
              <div className="text-xs text-text-secondary mt-1 truncate">
                {indicators.length > 0 ? indicators[0].value : 'None observed'}
              </div>
            </motion.div>

            <motion.div
              whileHover={{ scale: 1.02 }}
              className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                selectedNode === 'attachments'
                  ? 'border-accent-red bg-accent-red/10 shadow-[0_0_20px_rgba(255,112,132,0.2)]'
                  : 'border-white/10 bg-bg-secondary/70 hover:border-white/20'
              }`}
              onClick={() => setSelectedNode('attachments')}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold uppercase text-accent-red flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5" /> Attachments ({attachments.length})
                </span>
                <span className="text-[10px] font-mono text-text-muted">Binaries</span>
              </div>
              <div className="text-xs text-text-secondary mt-1 truncate">
                {attachments.length > 0 ? attachments[0].filename : 'No attachments'}
              </div>
            </motion.div>
          </div>

          {/* Column 4: VERDICT DECISION */}
          <motion.div
            whileHover={{ scale: 1.02 }}
            className={`p-5 rounded-xl border transition-all cursor-pointer text-center ${
              isHighRisk
                ? 'border-accent-red/40 bg-accent-red/10 shadow-[0_0_25px_rgba(255,112,132,0.25)]'
                : 'border-accent-green/40 bg-accent-green/10 shadow-[0_0_25px_rgba(94,230,168,0.25)]'
            }`}
            onClick={() => setSelectedNode('verdict')}
          >
            <div className="text-xs font-mono font-bold uppercase text-text-muted mb-1">Final Risk Score</div>
            <div className="text-3xl font-black font-mono text-white mb-2">
              {investigation.riskScore}
              <span className="text-sm font-normal text-text-muted">/100</span>
            </div>
            <span
              className={`inline-block px-3 py-1 rounded-md text-xs font-bold font-mono uppercase ${
                isHighRisk ? 'bg-accent-red text-bg-primary' : 'bg-accent-green text-bg-primary'
              }`}
            >
              {investigation.verdict}
            </span>
          </motion.div>
        </div>
      </div>

      {/* Detail Inspector Drawer for Selected Node */}
      {selectedNode && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="p-5 rounded-xl border border-white/10 bg-bg-secondary/60 backdrop-blur-md space-y-3"
        >
          <div className="flex items-center justify-between border-b border-white/5 pb-2">
            <span className="text-xs uppercase font-mono font-semibold text-accent-cyan">
              Inspector: {selectedNode.toUpperCase()}
            </span>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-xs text-text-muted hover:text-text-primary font-mono"
            >
              ✕ Close
            </button>
          </div>

          {selectedNode === 'sender' && (
            <div className="text-xs space-y-1 text-text-secondary font-mono">
              <p>Address: <span className="text-white">{sender}</span></p>
              <p>Host: <span className="text-white">{senderDomain}</span></p>
              <p>Reputation Score: <span className="text-accent-cyan">{isHighRisk ? 'High Risk Domain' : 'Standard'}</span></p>
            </div>
          )}

          {selectedNode === 'indicators' && (
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {indicators.map((ind, i) => (
                <div key={i} className="flex items-center justify-between text-xs p-2 rounded bg-bg-tertiary/50 font-mono">
                  <span className="text-accent-cyan truncate max-w-md">{ind.value}</span>
                  <span className="text-[10px] uppercase text-text-muted">{ind.type}</span>
                </div>
              ))}
            </div>
          )}

          {selectedNode === 'attachments' && (
            <div className="space-y-2">
              {attachments.map((att, i) => (
                <div key={i} className="flex items-center justify-between text-xs p-2 rounded bg-bg-tertiary/50 font-mono">
                  <span className="text-white">{att.filename}</span>
                  <span className={att.isSuspicious ? 'text-accent-red font-bold' : 'text-accent-green'}>
                    {att.isSuspicious ? 'Suspicious' : 'Clean'}
                  </span>
                </div>
              ))}
            </div>
          )}

          {selectedNode === 'verdict' && (
            <div className="text-xs space-y-1 text-text-secondary">
              <p>Ensemble Verdict: <span className="text-white font-bold">{investigation.verdict}</span></p>
              <p>Threat Assessment: Risk score of {investigation.riskScore}/100 synthesized from 80-feature ML ensemble and 200+ rule triggers.</p>
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
};
