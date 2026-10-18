'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  AlertTriangle,
  Search,
  Filter,
  RefreshCw,
  ArrowRight,
  ShieldAlert,
  Info,
  CheckCircle2,
} from 'lucide-react';
import { api } from '@/lib/api';
import { ThreatFinding } from '@/types/sentinelz';
import { SeverityBadge, StatusBadge } from '@/components/Badge';
import { useAuth } from '@/context/AuthContext';

export default function ThreatFindingsPage() {
  const { activeRole } = useAuth();
  const [findings, setFindings] = useState<ThreatFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState<string>('');
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [searchIdentity, setSearchIdentity] = useState<string>('');

  const fetchFindings = async () => {
    setLoading(true);
    try {
      const data = await api.getFindings({
        severity: filterSeverity || undefined,
        status: filterStatus || undefined,
      });
      setFindings(data);
    } catch (err) {
      console.error('Failed to load findings:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [filterSeverity, filterStatus]);

  const filteredFindings = findings.filter((f) => {
    if (!searchIdentity) return true;
    return (
      f.affected_identity.toLowerCase().includes(searchIdentity.toLowerCase()) ||
      f.title.toLowerCase().includes(searchIdentity.toLowerCase()) ||
      f.rule_id.toLowerCase().includes(searchIdentity.toLowerCase())
    );
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-4 border-b border-slate-800 gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center space-x-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <span>Explainable Threat Findings</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Rule-correlated anomalies, deterministic risk calculations, and non-destructive triage.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={fetchFindings}
            className="flex items-center space-x-1 px-3 py-1.5 text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Explanatory Callout: Facts vs Inferences */}
      <div className="p-3.5 rounded-lg bg-blue-950/30 border border-blue-900/40 text-xs font-mono text-slate-300 flex items-start space-x-3">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-semibold text-blue-200">Governance Principle: Distinguish Facts from Inferences</span>
          <p className="text-[11px] text-slate-400">
            SentinelZ AI distinguishes observed security facts from rule correlations, statistical scores, and confirmed incidents.
            An alert is an investigation hypothesis, not a confirmed cyberattack until verified by a security analyst.
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col md:flex-row gap-3 items-center justify-between p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono">
        <div className="relative flex-1 md:w-72">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
          <input
            type="text"
            placeholder="Search identity, title, or rule ID..."
            value={searchIdentity}
            onChange={(e) => setSearchIdentity(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center space-x-2">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
          >
            <option value="">All Statuses</option>
            <option value="OPEN">OPEN</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
          </select>
        </div>
      </div>

      {/* Findings List */}
      <div className="space-y-3">
        {filteredFindings.length > 0 ? (
          filteredFindings.map((f) => (
            <div
              key={f.id}
              className="p-4 rounded-lg bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition-all space-y-3"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                <div className="flex items-center space-x-2.5 flex-wrap">
                  <SeverityBadge severity={f.severity} />
                  <span className="font-semibold text-sm text-slate-100">{f.title}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                    {f.rule_id}
                  </span>
                </div>
                <div className="flex items-center space-x-3 text-xs font-mono">
                  <div className="flex items-center space-x-1">
                    <span className="text-slate-400">Risk Score:</span>
                    <span
                      className={`font-bold ${
                        f.risk_score >= 80 ? 'text-red-400' : f.risk_score >= 60 ? 'text-amber-400' : 'text-blue-400'
                      }`}
                    >
                      {f.risk_score} / 100
                    </span>
                  </div>
                  <StatusBadge status={f.status} />
                </div>
              </div>

              {/* Explanation & Evidence Summary */}
              <p className="text-xs text-slate-300 leading-relaxed font-mono">
                {f.explanation}
              </p>

              {/* Footer info & CTA */}
              <div className="pt-2 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono text-slate-400">
                <div className="flex items-center space-x-4">
                  <span>
                    Affected Identity: <strong className="text-slate-200">{f.affected_identity}</strong>
                  </span>
                  <span>
                    Method: <span className="text-slate-300">{f.detection_method}</span>
                  </span>
                  <span>
                    Generated: <span className="text-slate-400">{new Date(f.created_at).toLocaleTimeString()}</span>
                  </span>
                </div>

                <Link
                  href={`/findings/${f.id}`}
                  className="inline-flex items-center space-x-1.5 px-3 py-1 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 transition-colors self-start sm:self-auto"
                >
                  <span>Investigate Finding</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </div>
            </div>
          ))
        ) : (
          <div className="p-12 text-center rounded-lg border border-slate-800 bg-slate-900/40 text-xs font-mono text-slate-400 space-y-2">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
            <p className="text-slate-200 font-semibold">No Threat Findings Found</p>
            <p>No active anomalies match your filters. Ingest new security events or adjust your search.</p>
          </div>
        )}
      </div>
    </div>
  );
}
