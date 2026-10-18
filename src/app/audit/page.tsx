'use client';

import React, { useState, useEffect } from 'react';
import {
  FileText,
  Search,
  RefreshCw,
  Lock,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { api } from '@/lib/api';
import { AuditRecord } from '@/types/sentinelz';

export default function AuditTrailPage() {
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterAction, setFilterAction] = useState<string>('');
  const [filterOutcome, setFilterOutcome] = useState<string>('');
  const [searchActor, setSearchActor] = useState<string>('');
  const [selectedRecord, setSelectedRecord] = useState<AuditRecord | null>(null);

  const fetchAudit = async () => {
    setLoading(true);
    try {
      const data = await api.getAuditTrail({
        limit: 100,
        action: filterAction || undefined,
        outcome: filterOutcome || undefined,
        actor_id: searchActor || undefined,
      });
      setRecords(data);
    } catch (err) {
      console.error('Failed to load audit trail:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAudit();
  }, [filterAction, filterOutcome]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchAudit();
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-4 border-b border-slate-800 gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center space-x-2">
            <FileText className="w-5 h-5 text-blue-400" />
            <span>Immutable Governance Audit Trail</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Append-only security action log with cryptographic correlation IDs and zero-leakage redaction.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={fetchAudit}
            className="flex items-center space-x-1 px-3 py-1.5 text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Governance & Anti-Tamper Notice */}
      <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1.5 text-xs font-mono">
        <div className="flex items-center space-x-2 text-slate-200 font-semibold">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>Append-Only Application Architecture Notice</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          The SentinelZ audit trail operates on strict append-only semantics. Application endpoints deny edit, update, and delete verbs across all roles.
          Sensitive items (passwords, bearer tokens, cryptographic keys, and unredacted privacy texts) are scrubbed before persistence.
          <em> Note: While enforced by application logic, this is not equivalent to independently notarized hardware write-once-read-many (WORM) storage.</em>
        </p>
      </div>

      {/* Search & Filters */}
      <div className="flex flex-col md:flex-row gap-3 items-center justify-between p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono">
        <form onSubmit={handleSearchSubmit} className="flex items-center space-x-2 w-full md:w-auto">
          <div className="relative flex-1 md:w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search Actor ID..."
              value={searchActor}
              onChange={(e) => setSearchActor(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-slate-200 placeholder-slate-500 focus:border-blue-500 focus:outline-none"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded transition-colors"
          >
            Filter
          </button>
        </form>

        <div className="flex items-center space-x-2">
          <select
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
          >
            <option value="">All Security Actions</option>
            <option value="AUTH_LOGIN">AUTH_LOGIN</option>
            <option value="AUTH_FAILURE">AUTH_FAILURE</option>
            <option value="EVENT_INGESTED">EVENT_INGESTED</option>
            <option value="FINDING_STATUS_CHANGE">FINDING_STATUS_CHANGE</option>
            <option value="PRIVACY_SHIELD_RUN">PRIVACY_SHIELD_RUN</option>
            <option value="PRIVACY_AI_INFERENCE">PRIVACY_AI_INFERENCE</option>
            <option value="CONFIG_CHANGE">CONFIG_CHANGE</option>
            <option value="USER_ROLE_CHANGE">USER_ROLE_CHANGE</option>
            <option value="DEMO_RESEED">DEMO_RESEED</option>
          </select>

          <select
            value={filterOutcome}
            onChange={(e) => setFilterOutcome(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
          >
            <option value="">All Outcomes</option>
            <option value="SUCCESS">SUCCESS</option>
            <option value="DENIED">DENIED</option>
            <option value="FAILURE">FAILURE</option>
          </select>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider">
              <tr>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Action</th>
                <th className="py-2.5 px-4">Actor / Role</th>
                <th className="py-2.5 px-4">Target Entity</th>
                <th className="py-2.5 px-4">Outcome</th>
                <th className="py-2.5 px-4">Correlation ID</th>
                <th className="py-2.5 px-4 text-right">Context</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {records.length > 0 ? (
                records.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                      {new Date(r.timestamp).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-4 font-semibold text-slate-100">{r.action}</td>
                    <td className="py-2.5 px-4">
                      <div className="text-slate-200">{r.actor_id}</div>
                      <div className="text-[10px] text-slate-500">{r.actor_role}</div>
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">
                      {r.target_type}: {r.target_id || 'N/A'}
                    </td>
                    <td className="py-2.5 px-4">
                      <span
                        className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border ${
                          r.outcome === 'SUCCESS'
                            ? 'bg-emerald-950/80 text-emerald-400 border-emerald-800'
                            : 'bg-rose-950/80 text-rose-400 border-rose-800'
                        }`}
                      >
                        {r.outcome}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-500 text-[11px] font-mono">{r.request_id}</td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => setSelectedRecord(r)}
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-mono text-xs">
                    No audit records match the current filter selection.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Inspect Modal */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-lg w-full p-6 space-y-4 shadow-2xl font-mono text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h2 className="text-sm font-bold text-slate-100">
                Audit Record #{selectedRecord.id}: {selectedRecord.action}
              </h2>
              <button
                onClick={() => setSelectedRecord(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                &times;
              </button>
            </div>

            <div className="space-y-2 text-slate-300">
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-500">Timestamp:</span>
                <span>{new Date(selectedRecord.timestamp).toISOString()}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-500">Correlation ID:</span>
                <span className="text-cyan-400">{selectedRecord.request_id}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-500">Actor Identity:</span>
                <span>{selectedRecord.actor_id} ({selectedRecord.actor_role})</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-500">Target:</span>
                <span>{selectedRecord.target_type} / {selectedRecord.target_id || 'GLOBAL'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-500">Client Source IP:</span>
                <span>{selectedRecord.client_ip}</span>
              </div>
              <div className="space-y-1 pt-2">
                <span className="text-slate-500">Sanitized Context Metadata:</span>
                <pre className="p-3 bg-slate-950 rounded border border-slate-800 text-[11px] text-slate-300 overflow-x-auto">
                  {JSON.stringify(selectedRecord.context_metadata, null, 2)}
                </pre>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedRecord(null)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
