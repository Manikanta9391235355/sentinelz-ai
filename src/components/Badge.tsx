import React from 'react';
import { SeverityLevel, FindingStatus, AccessDecision } from '@/types/sentinelz';

interface SeverityBadgeProps {
  severity: SeverityLevel | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const sev = severity?.toUpperCase();
  const styles = {
    CRITICAL: 'bg-red-950/80 text-red-400 border border-red-800/80',
    HIGH: 'bg-amber-950/80 text-amber-400 border border-amber-800/80',
    MEDIUM: 'bg-yellow-950/80 text-yellow-400 border border-yellow-800/80',
    LOW: 'bg-blue-950/80 text-blue-400 border border-blue-800/80',
    CLEAN: 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/80',
  }[sev] || 'bg-slate-800 text-slate-300 border border-slate-700';

  const sizeClass = size === 'sm' ? 'px-1.5 py-0.5 text-xs' : 'px-2.5 py-1 text-xs font-semibold';

  return (
    <span className={`inline-flex items-center rounded-md font-mono tracking-wide ${styles} ${sizeClass}`}>
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current animate-pulse" />
      {sev}
    </span>
  );
};

export const StatusBadge: React.FC<{ status: FindingStatus | string }> = ({ status }) => {
  const st = status?.toUpperCase();
  const styles = {
    OPEN: 'bg-red-900/40 text-red-300 border border-red-700/60',
    INVESTIGATING: 'bg-cyan-900/40 text-cyan-300 border border-cyan-700/60',
    RESOLVED: 'bg-emerald-900/40 text-emerald-300 border border-emerald-700/60',
    FALSE_POSITIVE: 'bg-slate-800 text-slate-400 border border-slate-700',
  }[st] || 'bg-slate-800 text-slate-300 border border-slate-700';

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${styles}`}>
      {st}
    </span>
  );
};

export const DecisionBadge: React.FC<{ decision: AccessDecision | string }> = ({ decision }) => {
  const dec = decision?.toUpperCase();
  const isAllow = dec === 'ALLOW';
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold border ${
        isAllow
          ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
          : 'bg-rose-950/60 text-rose-400 border-rose-800/60'
      }`}
    >
      {isAllow ? '✓ ALLOW' : '✕ DENY'}
    </span>
  );
};
