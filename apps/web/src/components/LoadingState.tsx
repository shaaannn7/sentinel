import React from 'react';

interface LoadingStateProps {
  message?: string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const sizeClasses = {
  sm: 'w-5 h-5 border-2',
  md: 'w-8 h-8 border-2',
  lg: 'w-12 h-12 border-3',
};

export default function LoadingState({ message, size = 'md', className }: LoadingStateProps) {
  return (
    <div className={className}>
      <div className="flex flex-col items-center justify-center py-12">
        <div className={`rounded-full border-accent-cyan border-t-transparent animate-spin ${sizeClasses[size]}`} />
        {message && (
          <p className="text-text-secondary mt-4 text-center">{message}</p>
        )}
      </div>
    </div>
  );
}