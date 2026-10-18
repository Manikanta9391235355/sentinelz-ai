'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ShieldAlert,
  AlertTriangle,
  Lock,
  UserX,
  FileText,
  ArrowUpRight,
  TrendingUp,
  RefreshCw,
  Cpu,
  Info,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
} from 'recharts';
import { api } from '@/lib/api';
import { DashboardMetrics } from '@/types/sentinelz';
import { SeverityBadge, StatusBadge, DecisionBadge } from '@/components/Badge';
import { useAuth } from '@/context/AuthContext';

export default function OverviewPage() {
  const { user, loading: authLoading } = useAuth();
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getDashboardMetrics();
      setMetrics(data);
    } catch (err: any) {
      console.error('Failed to load dashboard metrics:', err);
      setError(err.message || 'Failed to connect to SentinelZ security telemetry service.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!authLoading) {
      fetchMetrics();
    }
  }, [authLoading, user]);

  if (loading && !metrics) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-3">
        <RefreshCw className="w-8 h-8 text-blue-500 animate-spin" />
        <p className="text-sm font-mono text-slate-400">Loading SentinelZ security operations telemetry...</p>
      </div>
    );
  }

  if (error && !metrics) {
    return (
      <div className="p-6 rounded-lg bg-red-950/40 border border-red-800/80 text-red-200 max-w-2xl mx-auto my-12 space-y-3">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="w-5 h-5 text-red-400" />
          <h2 className="text-base font-semibold">Backend Connection Unavailable</h2>
        </div>
        <p className="text-xs font-mono text-red-300">{error}</p>
        <p className="text-xs text-slate-400">
          Ensure the FastAPI backend is running via <code className="bg-slate-900 px-1 py-0.5 rounded text-blue-300">python -m uvicorn backend.app.main:app --port 8000 --reload</code>
        </p>
        <button
          onClick={fetchMetrics}
          className="px-3 py-1.5 bg-red-800 hover:bg-red-700 text-white rounded text-xs font-mono transition-colors"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const severityChartData = [
    { name: 'Critical', count: metrics?.severity_distribution.critical || 0, color: '#ef4444' },
    { name: 'High', count: metrics?.severity_distribution.high || 0, color: '#f97316' },
    { name: 'Medium', count: metrics?.severity_distribution.medium || 0, color: '#eab308' },
    { name: 'Low', count: metrics?.severity_distribution.low || 0, color: '#3b82f6' },
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Banner / Headline */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-4 border-b border-slate-800 gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center space-x-2">
            <span>Security Operations Center</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800">
              Live SOC Telemetry
            </span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Enterprise threat detection, explainable rule correlation, and non-exposure PII protection.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-slate-400 px-2 py-1 bg-slate-900 border border-slate-800 rounded">
            Simulated Demo Mode: <span className="text-emerald-400 font-semibold">Active</span>
          </span>
          <button
            onClick={fetchMetrics}
            className="flex items-center space-x-1 px-2.5 py-1 text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Total Events */}
        <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Total Events</span>
            <ShieldAlert className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-slate-100">{metrics?.total_events ?? 0}</span>
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Ingested security events</p>
        </div>

        {/* High Risk Events */}
        <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>High-Risk Findings</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-amber-400">{metrics?.high_risk_events ?? 0}</span>
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Risk score &ge; 60 / 100</p>
        </div>

        {/* Events Requiring Investigation */}
        <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Under Investigation</span>
            <TrendingUp className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-rose-400">{metrics?.open_findings_count ?? 0}</span>
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Unresolved security alerts</p>
        </div>

        {/* Unauthorized Denials */}
        <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>Denied Access</span>
            <UserX className="w-4 h-4 text-purple-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-purple-400">{metrics?.unauthorized_access_attempts ?? 0}</span>
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Blocked perimeter attempts</p>
        </div>

        {/* Sensitive Data Redactions */}
        <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>PII Shielded</span>
            <Lock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">{metrics?.sensitive_data_redactions ?? 0}</span>
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Tokens neutralized by Shield</p>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Event Volume Over Time (2 cols) */}
        <div className="lg:col-span-2 p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-slate-200">Event Volume &amp; Anomaly Distribution</h2>
              <p className="text-[11px] text-slate-400 font-mono">Temporal sliding window tracking across operational hours</p>
            </div>
            <div className="flex items-center space-x-3 text-xs font-mono">
              <span className="flex items-center">
                <span className="w-2.5 h-2.5 rounded-sm bg-blue-500 mr-1.5" /> Events
              </span>
              <span className="flex items-center">
                <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 mr-1.5" /> Denied
              </span>
              <span className="flex items-center">
                <span className="w-2.5 h-2.5 rounded-sm bg-amber-400 mr-1.5" /> Anomalies
              </span>
            </div>
          </div>

          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={metrics?.event_volume_trend || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorDenied" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time_label" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="event_count" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorEvents)" name="Events" />
                <Area type="monotone" dataKey="denied_count" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorDenied)" name="Denied" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Breakdown (1 col) */}
        <div className="p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-4 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Severity Distribution</h2>
            <p className="text-[11px] text-slate-400 font-mono">Findings grouped by calculated risk severity</p>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityChartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '12px' }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80 text-xs font-mono">
            <div className="flex items-center justify-between px-2 py-1 bg-red-950/30 rounded border border-red-900/40">
              <span className="text-red-400">Critical:</span>
              <span className="font-bold text-red-300">{metrics?.severity_distribution.critical || 0}</span>
            </div>
            <div className="flex items-center justify-between px-2 py-1 bg-amber-950/30 rounded border border-amber-900/40">
              <span className="text-amber-400">High:</span>
              <span className="font-bold text-amber-300">{metrics?.severity_distribution.high || 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Findings and Recent Audit Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Threat Findings */}
        <div className="p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-slate-200">Recent Threat Findings</h2>
              <p className="text-[11px] text-slate-400 font-mono">Explainable alerts correlated by detection engine</p>
            </div>
            <Link
              href="/findings"
              className="text-xs font-mono text-blue-400 hover:text-blue-300 flex items-center space-x-1"
            >
              <span>View All</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {metrics?.recent_findings && metrics.recent_findings.length > 0 ? (
            <div className="space-y-2.5">
              {metrics.recent_findings.map((f) => (
                <Link
                  key={f.id}
                  href={`/findings/${f.id}`}
                  className="block p-3 rounded-md bg-slate-950/70 border border-slate-800 hover:border-blue-500/40 transition-colors"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <SeverityBadge severity={f.severity} size="sm" />
                        <span className="text-xs font-medium text-slate-200 hover:text-blue-300">{f.title}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 font-mono line-clamp-1">{f.explanation}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <div className="text-xs font-mono font-bold text-slate-100">{f.risk_score} / 100</div>
                      <StatusBadge status={f.status} />
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <div className="p-6 text-center text-xs text-slate-400 font-mono">
              No threat findings generated yet. Ingest security events or reseed demo data.
            </div>
          )}
        </div>

        {/* Latest Audit Events */}
        <div className="p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-slate-200">Append-Only Audit Trail Stream</h2>
              <p className="text-[11px] text-slate-400 font-mono">Immutable governance log with zero sensitive leakage</p>
            </div>
            <Link
              href="/audit"
              className="text-xs font-mono text-blue-400 hover:text-blue-300 flex items-center space-x-1"
            >
              <span>Full Log</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {metrics?.recent_audit && metrics.recent_audit.length > 0 ? (
            <div className="space-y-2">
              {metrics.recent_audit.map((a) => (
                <div
                  key={a.id}
                  className="p-2.5 rounded-md bg-slate-950/70 border border-slate-800/80 flex items-center justify-between text-xs font-mono"
                >
                  <div className="flex items-center space-x-2.5 truncate">
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        a.outcome === 'SUCCESS' ? 'bg-emerald-400' : 'bg-red-400'
                      }`}
                    />
                    <span className="text-slate-300 font-semibold">{a.action}</span>
                    <span className="text-slate-500 truncate max-w-[140px]">{a.actor_id}</span>
                  </div>
                  <div className="text-right text-[11px] text-slate-400 shrink-0">
                    <span>{new Date(a.timestamp).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-6 text-center text-xs text-slate-400 font-mono">
              No audit entries recorded yet.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
