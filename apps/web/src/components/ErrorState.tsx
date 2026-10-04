import React from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  className?: string;
}

export default function ErrorState({ title = 'Something went wrong', message, onRetry, className }: ErrorStateProps) {
  return (
    <div className={`text-center py-12 px-4 ${className || ''}`}>
      <div className="w-16 h-16 rounded-xl bg-accent-red/10 flex items-center justify-center mx-auto mb-4 text-accent-red">
        <AlertCircle className="w-8 h-8" />
      </div>
      <h3 className="text-lg font-medium text-text-primary">{title}</h3>
      <p className="text-text-secondary mt-1 max-w-xs mx-auto">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-6 inline-flex items-center gap-2 px-4 py-2 bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20 rounded-lg hover:bg-accent-cyan/20 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Try Again
        </button>
      )}
    </div>
  );
}