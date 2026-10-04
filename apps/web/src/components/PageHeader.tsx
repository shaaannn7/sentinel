import React from 'react';

interface PageHeaderProps {
  title: string;
  description?: string;
  action?: React.ReactNode;
  children?: React.ReactNode;
}

export default function PageHeader({ title, description, action, children }: PageHeaderProps) {
  return (
    <header className={`mb-6 ${action ? 'flex items-start justify-between gap-4' : ''}`}>
      <div>
        <h1 className="text-2xl font-semibold text-text-primary tracking-tight">{title}</h1>
        {description && (
          <p className="text-text-secondary mt-1 max-w-2xl">{description}</p>
        )}
        {children}
      </div>
      {action && (
        <div className="flex-shrink-0 mt-2 md:mt-0">{action}</div>
      )}
    </header>
  );
}