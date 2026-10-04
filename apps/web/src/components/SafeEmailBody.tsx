import React, { useEffect, useState } from 'react';
import DOMPurify from 'dompurify';
import { ShieldCheck, Eye, FileText, AlertTriangle } from 'lucide-react';

interface SafeEmailBodyProps {
  htmlBody?: string;
  textBody?: string;
  plainBody?: string;
}

export const SafeEmailBody: React.FC<SafeEmailBodyProps> = ({ htmlBody, textBody, plainBody }) => {
  const effectiveText = textBody || plainBody || '';
  const [sanitizedHtml, setSanitizedHtml] = useState<string>('');
  const [viewMode, setViewMode] = useState<'html' | 'text'>(htmlBody ? 'html' : 'text');

  useEffect(() => {
    if (typeof window !== 'undefined' && htmlBody) {
      // Strict client-side sanitization policy
      const clean = DOMPurify.sanitize(htmlBody, {
        ALLOWED_TAGS: [
          'a', 'b', 'blockquote', 'br', 'code', 'div', 'em', 'h1', 'h2', 'h3',
          'h4', 'h5', 'h6', 'hr', 'i', 'li', 'ol', 'p', 'pre', 'span',
          'strong', 'table', 'tbody', 'td', 'th', 'thead', 'tr', 'u', 'ul',
        ],
        ALLOWED_ATTR: ['href', 'title', 'target', 'rel', 'class'],
        FORBID_TAGS: [
          'script', 'iframe', 'object', 'embed', 'form', 'svg', 'math',
          'base', 'link', 'style', 'img', 'video', 'audio', 'canvas',
        ],
        FORBID_ATTR: [
          'style', 'src', 'onerror', 'onload', 'onclick', 'onmouseover',
          'onfocus', 'onblur', 'formaction',
        ],
        RETURN_TRUSTED_TYPE: false,
      });

      // Enforce safe link targets
      DOMPurify.addHook('afterSanitizeAttributes', (node) => {
        if ('target' in node) {
          node.setAttribute('target', '_blank');
          node.setAttribute('rel', 'noopener noreferrer nofollow');
        }
      });

      setSanitizedHtml(clean);
    }
  }, [htmlBody]);

  if (!htmlBody && !effectiveText) {
    return <p className="text-text-secondary text-sm">No body content available</p>;
  }

  return (
    <div className="space-y-3">
      {/* Security notice & view mode toggles */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-lg bg-bg-secondary/70 border border-border-default text-xs font-mono">
        <div className="flex items-center gap-2 text-accent-green">
          <ShieldCheck className="w-4 h-4 text-accent-green" />
          <span>Active content, scripts, and external tracking pixels isolated</span>
        </div>
        <div className="flex items-center gap-1 bg-bg-tertiary rounded p-0.5 border border-border-default">
          {htmlBody && (
            <button
              type="button"
              onClick={() => setViewMode('html')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs transition-colors ${
                viewMode === 'html'
                  ? 'bg-accent-cyan text-bg-primary font-semibold'
                  : 'text-text-secondary hover:text-text-primary'
              }`}
            >
              <Eye className="w-3.5 h-3.5" /> Sanitized HTML
            </button>
          )}
          {effectiveText && (
            <button
              type="button"
              onClick={() => setViewMode('text')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs transition-colors ${
                viewMode === 'text'
                  ? 'bg-accent-cyan text-bg-primary font-semibold'
                  : 'text-text-secondary hover:text-text-primary'
              }`}
            >
              <FileText className="w-3.5 h-3.5" /> Plain Text
            </button>
          )}
        </div>
      </div>

      {/* Render View */}
      {viewMode === 'html' && htmlBody ? (
        <div className="bg-bg-tertiary rounded-lg p-5 border border-border-default overflow-x-auto text-text-primary text-sm leading-relaxed">
          {sanitizedHtml ? (
            <div
              className="prose prose-invert max-w-none break-words"
              dangerouslySetInnerHTML={{ __html: sanitizedHtml }}
            />
          ) : (
            <div className="text-text-secondary font-mono text-xs">Sanitizing content...</div>
          )}
        </div>
      ) : (
        <div className="bg-bg-tertiary rounded-lg p-4 font-mono text-text-secondary border border-border-default text-xs overflow-x-auto">
          <pre className="whitespace-pre-wrap break-all">{effectiveText || 'No text body'}</pre>
        </div>
      )}
    </div>
  );
};

export default SafeEmailBody;
