import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { Activity, Brain, Command, FileSearch, LayoutDashboard, Menu, Radar, ShieldCheck, X } from 'lucide-react';

const navigation = [
  { href: '/', label: 'Overview', icon: LayoutDashboard },
  { href: '/investigations', label: 'Investigations', icon: FileSearch },
  { href: '/brain', label: 'Brain & ML', icon: Brain },
  { href: '/indicators', label: 'Indicators', icon: Radar },
  { href: '/reports', label: 'Reports', icon: Activity },
];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const router = useRouter();

  const navItems = navigation.map((item) => ({
    ...item,
    active: item.href === '/' ? router.pathname === '/' : router.pathname.startsWith(item.href),
  }));

  return (
    <div className="min-h-screen bg-bg-primary text-text-primary flex flex-col">
      {/* Desktop Sidebar */}
      <aside className="hidden md:flex flex-col w-64 bg-bg-secondary border-r border-border-default fixed inset-y-0 left-0 z-50">
        <div className="px-7 py-6 border-b border-border-default">
          <div className="flex items-center gap-2">
            <div className="w-9 h-9 rounded-lg bg-accent-cyan flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-bg-primary" />
            </div>
            <div>
              <span className="font-semibold text-lg tracking-[0.12em]">SENTINEL</span>
              <p className="text-[10px] uppercase tracking-[0.22em] text-text-muted">Threat intelligence</p>
            </div>
          </div>
        </div>
        <nav className="flex-1 px-4 py-6 space-y-2">
          <p className="eyebrow px-3 mb-3">Workspace</p>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-3 rounded-xl transition-all ${
                item.active
                  ? 'bg-accent-cyan/10 text-text-primary ring-1 ring-accent-cyan/20'
                  : 'text-text-secondary hover:bg-bg-tertiary hover:text-text-primary'
              }`}
            >
              <Icon className={`w-4 h-4 ${item.active ? 'text-accent-cyan' : 'text-text-muted'}`} />
              <span className="font-medium">{item.label}</span>
            </Link>
            );
          })}
        </nav>
        <div className="mx-4 mb-4 rounded-lg border border-border-default bg-bg-tertiary p-3">
          <div className="flex items-center gap-2 text-xs text-text-secondary">
            <Command className="w-4 h-4 text-accent-purple" />
            <span>CLI connected</span>
          </div>
          <p className="text-xs text-text-muted mt-2 leading-relaxed">Switch between the browser workspace and terminal workflows at any time.</p>
        </div>
        <div className="px-7 py-4 border-t border-border-default">
          <div className="flex items-center gap-2 text-xs text-text-muted">
            <div className="w-2 h-2 rounded-full bg-accent-green shadow-[0_0_10px_rgba(94,230,168,0.8)]"></div>
            <span>All systems operational</span>
          </div>
        </div>
      </aside>

      {/* Mobile Header */}
      <header className="md:hidden flex items-center justify-between p-4 border-b border-border-default bg-bg-secondary/90">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-sm bg-accent-cyan flex items-center justify-center">
            <span className="font-mono font-bold text-bg-primary text-sm">S</span>
          </div>
          <span className="font-semibold text-lg">SENTINEL</span>
        </div>
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="p-2 text-text-secondary hover:text-text-primary"
        >
          {mobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </header>

      {/* Mobile Drawer */}
      <div
        className={`md:hidden fixed inset-y-0 left-0 w-64 bg-bg-secondary border-r border-border-default z-40 transition-transform duration-300 ease-in-out ${mobileMenuOpen ? 'translate-x-0' : '-translate-x-full'}`}
      >
        <div className="px-6 py-5 border-b border-border-default">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-sm bg-accent-cyan flex items-center justify-center">
              <span className="font-mono font-bold text-bg-primary text-sm">S</span>
            </div>
            <span className="font-semibold text-lg">SENTINEL</span>
          </div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {navigation.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="block px-3 py-2 rounded text-text-secondary hover:bg-bg-tertiary hover:text-text-primary transition-colors"
              onClick={() => setMobileMenuOpen(false)}
            >
              {item.label}
            </Link>
          ))}
        </nav>
        <div className="px-6 py-3 border-t border-border-default">
          <div className="flex items-center gap-2 text-xs text-text-muted">
            <div className="w-2 h-2 rounded-full bg-accent-green"></div>
            <span>Operational</span>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <main className="flex-1 md:ml-64 overflow-y-auto">
        <div className="hidden md:flex items-center justify-between h-16 px-8 border-b border-border-default/70 bg-bg-primary/40">
          <div className="text-sm text-text-muted">Operations center <span className="mx-2 text-border-strong">/</span> {router.pathname === '/' ? 'Overview' : 'Investigation workspace'}</div>
          <div className="flex items-center gap-3 text-xs text-text-muted">
            <span className="inline-flex items-center gap-2"><span className="w-2 h-2 rounded-full bg-accent-green" />Live analysis engine</span>
            <span className="rounded-full border border-border-default px-3 py-1.5 font-mono">v0.1.0</span>
          </div>
        </div>
        {children}
      </main>
    </div>
  );
}