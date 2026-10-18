'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  ShieldAlert,
  Activity,
  AlertTriangle,
  Lock,
  Users,
  FileText,
  Server,
  Sliders,
  CheckCircle2,
  Eye,
  UserCheck,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { UserRole } from '@/types/sentinelz';

const NAV_ITEMS = [
  { name: 'Overview', href: '/', icon: Activity },
  { name: 'Security Events', href: '/events', icon: ShieldAlert },
  { name: 'Threat Findings', href: '/findings', icon: AlertTriangle },
  { name: 'Privacy Shield', href: '/privacy', icon: Lock },
  { name: 'Identity & Access', href: '/identity', icon: Users },
  { name: 'Audit Trail', href: '/audit', icon: FileText },
  { name: 'System Health', href: '/health', icon: Server },
  { name: 'Settings', href: '/settings', icon: Sliders },
];

export const Sidebar: React.FC = () => {
  const pathname = usePathname();
  const { user, activeRole, switchRole, loading } = useAuth();

  const getRoleBadge = (role: UserRole) => {
    switch (role) {
      case 'security_admin':
        return { label: 'Security Administrator', color: 'text-rose-400 bg-rose-950/80 border-rose-800' };
      case 'security_analyst':
        return { label: 'Security Analyst', color: 'text-cyan-400 bg-cyan-950/80 border-cyan-800' };
      case 'viewer':
        return { label: 'Compliance Viewer', color: 'text-slate-400 bg-slate-900 border-slate-700' };
    }
  };

  const currentBadge = getRoleBadge(activeRole);

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800 flex flex-col h-screen fixed left-0 top-0 z-30 select-none">
      {/* Brand Header */}
      <div className="p-4 border-b border-slate-800/80 bg-slate-950/90">
        <div className="flex items-center space-x-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-600 to-cyan-500 flex items-center justify-center text-white shadow-lg shadow-cyan-950/50">
            <span className="font-mono font-bold text-base tracking-tighter">SZ</span>
          </div>
          <div>
            <div className="flex items-center space-x-1.5">
              <span className="font-bold text-slate-100 tracking-tight text-sm">SentinelZ AI</span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 bg-blue-950 text-blue-400 border border-blue-800/60 rounded">
                IBM Z
              </span>
            </div>
            <p className="text-[11px] text-slate-400 tracking-tight font-mono">Intelligence Without Exposure</p>
          </div>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        <div className="px-3 pb-2 text-[10px] font-semibold text-slate-400 uppercase tracking-wider font-mono">
          Security Operations
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href));
          return (
            <Link
              key={item.name}
              href={item.href}
              className={`flex items-center px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                isActive
                  ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30'
                  : 'text-slate-300 hover:text-slate-100 hover:bg-slate-900/80 border border-transparent'
              }`}
            >
              <Icon className={`w-4 h-4 mr-2.5 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
              <span>{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* Datathon RBAC Demo Switcher */}
      <div className="p-3 border-t border-slate-800 bg-slate-950/95 space-y-2.5">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-400">
            Datathon RBAC Switcher
          </span>
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" title="Backend Live" />
        </div>

        {/* Active Identity Card */}
        <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-200 truncate">{user?.full_name || 'Loading user...'}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-mono border ${currentBadge.color}`}>
              {currentBadge.label}
            </span>
          </div>
          <p className="text-[10px] text-slate-400 font-mono truncate">{user?.email}</p>
        </div>

        {/* Persona Buttons */}
        <div className="grid grid-cols-3 gap-1 pt-1">
          <button
            onClick={() => switchRole('security_admin')}
            disabled={loading || activeRole === 'security_admin'}
            className={`px-1.5 py-1.5 rounded text-[10px] font-mono font-medium border text-center transition-all ${
              activeRole === 'security_admin'
                ? 'bg-rose-950/90 text-rose-300 border-rose-700 shadow-sm'
                : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-rose-300 hover:border-slate-700'
            }`}
            title="Administrator: Full administrative control, rule configuration, and system re-seeding"
          >
            Admin
          </button>
          <button
            onClick={() => switchRole('security_analyst')}
            disabled={loading || activeRole === 'security_analyst'}
            className={`px-1.5 py-1.5 rounded text-[10px] font-mono font-medium border text-center transition-all ${
              activeRole === 'security_analyst'
                ? 'bg-cyan-950/90 text-cyan-300 border-cyan-700 shadow-sm'
                : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-cyan-300 hover:border-slate-700'
            }`}
            title="Analyst: Event ingestion, threat investigation, status disposition, and privacy shield"
          >
            Analyst
          </button>
          <button
            onClick={() => switchRole('viewer')}
            disabled={loading || activeRole === 'viewer'}
            className={`px-1.5 py-1.5 rounded text-[10px] font-mono font-medium border text-center transition-all ${
              activeRole === 'viewer'
                ? 'bg-slate-800 text-slate-200 border-slate-600 shadow-sm'
                : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200 hover:border-slate-700'
            }`}
            title="Viewer: Aggregate metrics view only; denied admin and mutation endpoints"
          >
            Viewer
          </button>
        </div>

        {/* LinuxONE Readiness Footer Pill */}
        <div className="pt-1 flex items-center justify-between text-[10px] text-slate-400 font-mono">
          <span>Target Architecture</span>
          <span className="text-cyan-400 font-semibold">LinuxONE s390x</span>
        </div>
      </div>
    </aside>
  );
};
