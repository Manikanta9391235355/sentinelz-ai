'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Plus,
  Search,
  Filter,
  RefreshCw,
  Terminal,
  X,
  AlertCircle,
  CheckCircle,
} from 'lucide-react';
import { api } from '@/lib/api';
import { SecurityEvent } from '@/types/sentinelz';
import { DecisionBadge } from '@/components/Badge';
import { useAuth } from '@/context/AuthContext';

export default function SecurityEventsPage() {
  const { activeRole } = useAuth();
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterDecision, setFilterDecision] = useState<string>('');
  const [filterClassification, setFilterClassification] = useState<string>('');
  const [searchUser, setSearchUser] = useState<string>('');
  const [showIngestModal, setShowIngestModal] = useState<boolean>(false);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // Form state for ingestion
  const [ingestForm, setIngestForm] = useState({
    user_id: 'u_test_actor',
    user_role: 'operator',
    source_ip: '198.51.100.12',
    resource: 'mainframes/z16-hsm/crypto-keys/master-aes256',
    requested_action: 'READ',
    resource_classification: 'RESTRICTED_HIGH_VALUE',
    access_decision: 'DENY',
    auth_result: 'N/A',
  });
  const [ingesting, setIngesting] = useState(false);
  const [ingestStatus, setIngestStatus] = useState<string | null>(null);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const data = await api.getEvents({
        limit: 100,
        decision: filterDecision || undefined,
        classification: filterClassification || undefined,
        user_id: searchUser || undefined,
      });
      setEvents(data);
    } catch (err) {
      console.error('Failed to load events:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [filterDecision, filterClassification]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchEvents();
  };

  const loadScenarioTemplate = (scenario: string) => {
    if (scenario === 'HIGH_VALUE_UNAUTHORIZED') {
      setIngestForm({
        user_id: 'u_external_intruder',
        user_role: 'unauthenticated',
        source_ip: '203.0.113.88',
        resource: 'mainframes/z16-hsm/crypto-keys/master-aes256',
        requested_action: 'READ',
        resource_classification: 'RESTRICTED_HIGH_VALUE',
        access_decision: 'DENY',
        auth_result: 'N/A',
      });
    } else if (scenario === 'BRUTE_FORCE_AUTH') {
      setIngestForm({
        user_id: 'u_target_admin',
        user_role: 'unauthenticated',
        source_ip: '198.51.100.42',
        resource: 'api/v1/auth/login',
        requested_action: 'AUTHENTICATE',
        resource_classification: 'INTERNAL',
        access_decision: 'DENY',
        auth_result: 'FAILURE',
      });
    } else if (scenario === 'PRIVILEGE_MISMATCH') {
      setIngestForm({
        user_id: 'u_contractor_dev',
        user_role: 'contractor',
        source_ip: '10.142.9.14',
        resource: 'db/core/users/financial-records',
        requested_action: 'ADMIN_DELETE',
        resource_classification: 'CONFIDENTIAL',
        access_decision: 'DENY',
        auth_result: 'N/A',
      });
    } else {
      setIngestForm({
        user_id: 'u_ops_normal',
        user_role: 'operator',
        source_ip: '10.142.1.20',
        resource: 'api/v1/metrics/telemetry',
        requested_action: 'READ',
        resource_classification: 'INTERNAL',
        access_decision: 'ALLOW',
        auth_result: 'SUCCESS',
      });
    }
  };

  const handleIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    setIngesting(true);
    setIngestStatus(null);
    try {
      const res = await api.ingestEvent(ingestForm as any);
      setIngestStatus(`Event ${res.id} successfully ingested and evaluated!`);
      fetchEvents();
      setTimeout(() => {
        setShowIngestModal(false);
        setIngestStatus(null);
      }, 1500);
    } catch (err: any) {
      setIngestStatus(`Ingestion error: ${err.message}`);
    } finally {
      setIngesting(false);
    }
  };

  const canIngest = activeRole === 'security_admin' || activeRole === 'security_analyst';

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-4 border-b border-slate-800 gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-blue-400" />
            <span>Security Event Telemetry Stream</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Normalized security access events, audit outcomes, and authentication telemetry.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowIngestModal(true)}
            disabled={!canIngest}
            className={`flex items-center space-x-1.5 px-3 py-1.5 text-xs font-mono rounded font-semibold transition-colors ${
              canIngest
                ? 'bg-blue-600 hover:bg-blue-500 text-white shadow-md'
                : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
            }`}
            title={canIngest ? 'Ingest and evaluate a new security event' : 'RBAC Restriction: Viewer cannot ingest events'}
          >
            <Plus className="w-4 h-4" />
            <span>Ingest Security Event</span>
          </button>

          <button
            onClick={fetchEvents}
            className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 rounded transition-colors"
            title="Refresh stream"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* RBAC Notice if Viewer */}
      {!canIngest && (
        <div className="p-3 rounded bg-slate-900/80 border border-slate-800 text-xs font-mono text-slate-300 flex items-center space-x-2">
          <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>
            Active Persona: <strong className="text-slate-100">Viewer</strong>. You possess read-only access to security event records. Ingestion and mutation operations are enforced and blocked at the API level.
          </span>
        </div>
      )}

      {/* Filters & Search */}
      <div className="flex flex-col md:flex-row gap-3 items-center justify-between p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono">
        <form onSubmit={handleSearchSubmit} className="flex items-center space-x-2 w-full md:w-auto">
          <div className="relative flex-1 md:w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search by User ID..."
              value={searchUser}
              onChange={(e) => setSearchUser(e.target.value)}
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

        <div className="flex items-center space-x-2 w-full md:w-auto justify-end">
          <select
            value={filterDecision}
            onChange={(e) => setFilterDecision(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
          >
            <option value="">All Decisions</option>
            <option value="ALLOW">ALLOW only</option>
            <option value="DENY">DENY only</option>
          </select>

          <select
            value={filterClassification}
            onChange={(e) => setFilterClassification(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-300 focus:outline-none"
          >
            <option value="">All Classifications</option>
            <option value="PUBLIC">PUBLIC</option>
            <option value="INTERNAL">INTERNAL</option>
            <option value="CONFIDENTIAL">CONFIDENTIAL</option>
            <option value="RESTRICTED_HIGH_VALUE">RESTRICTED_HIGH_VALUE</option>
          </select>
        </div>
      </div>

      {/* Events Table */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Event ID</th>
                <th className="py-3 px-4">Identity / Role</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Target Resource</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Decision</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {events.length > 0 ? (
                events.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 font-semibold">{ev.id}</td>
                    <td className="py-2.5 px-4">
                      <div className="font-semibold text-slate-200">{ev.user_id}</div>
                      <div className="text-[10px] text-slate-500 font-mono">{ev.user_role}</div>
                    </td>
                    <td className="py-2.5 px-4 text-slate-400">{ev.source_ip}</td>
                    <td className="py-2.5 px-4 text-slate-200 max-w-[200px] truncate" title={ev.resource}>
                      {ev.resource}
                    </td>
                    <td className="py-2.5 px-4">
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded border ${
                          ev.resource_classification === 'RESTRICTED_HIGH_VALUE'
                            ? 'bg-rose-950 text-rose-300 border-rose-800'
                            : ev.resource_classification === 'CONFIDENTIAL'
                            ? 'bg-amber-950 text-amber-300 border-amber-800'
                            : 'bg-slate-800 text-slate-300 border-slate-700'
                        }`}
                      >
                        {ev.resource_classification}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">{ev.requested_action}</td>
                    <td className="py-2.5 px-4">
                      <DecisionBadge decision={ev.access_decision} />
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => setSelectedEvent(ev)}
                        className="px-2 py-1 text-[11px] rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500 font-mono text-xs">
                    No security events found matching current filter parameters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Ingest Security Event Modal */}
      {showIngestModal && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h2 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-blue-400" />
                <span>Ingest Synthetic Security Telemetry</span>
              </h2>
              <button
                onClick={() => setShowIngestModal(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick Scenario Templates */}
            <div className="space-y-1.5">
              <span className="text-[11px] font-mono text-slate-400">Quick Test Scenarios:</span>
              <div className="flex flex-wrap gap-1.5">
                <button
                  type="button"
                  onClick={() => loadScenarioTemplate('HIGH_VALUE_UNAUTHORIZED')}
                  className="px-2 py-1 bg-rose-950/70 hover:bg-rose-900 text-rose-300 border border-rose-800 rounded text-[10px] font-mono"
                >
                  High-Value Mainframe Asset Probe
                </button>
                <button
                  type="button"
                  onClick={() => loadScenarioTemplate('BRUTE_FORCE_AUTH')}
                  className="px-2 py-1 bg-amber-950/70 hover:bg-amber-900 text-amber-300 border border-amber-800 rounded text-[10px] font-mono"
                >
                  Auth Failure Burst
                </button>
                <button
                  type="button"
                  onClick={() => loadScenarioTemplate('PRIVILEGE_MISMATCH')}
                  className="px-2 py-1 bg-purple-950/70 hover:bg-purple-900 text-purple-300 border border-purple-800 rounded text-[10px] font-mono"
                >
                  Privilege Role Mismatch
                </button>
                <button
                  type="button"
                  onClick={() => loadScenarioTemplate('NORMAL')}
                  className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-[10px] font-mono"
                >
                  Normal Authorized Access
                </button>
              </div>
            </div>

            {/* Ingestion Form */}
            <form onSubmit={handleIngest} className="space-y-3 text-xs font-mono">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">User Identifier</label>
                  <input
                    type="text"
                    required
                    value={ingestForm.user_id}
                    onChange={(e) => setIngestForm({ ...ingestForm, user_id: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">User Role</label>
                  <input
                    type="text"
                    required
                    value={ingestForm.user_role}
                    onChange={(e) => setIngestForm({ ...ingestForm, user_role: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Source IP Address</label>
                  <input
                    type="text"
                    required
                    value={ingestForm.source_ip}
                    onChange={(e) => setIngestForm({ ...ingestForm, source_ip: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Requested Action</label>
                  <select
                    value={ingestForm.requested_action}
                    onChange={(e) => setIngestForm({ ...ingestForm, requested_action: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                  >
                    <option value="READ">READ</option>
                    <option value="WRITE">WRITE</option>
                    <option value="EXECUTE">EXECUTE</option>
                    <option value="AUTHENTICATE">AUTHENTICATE</option>
                    <option value="ADMIN_DELETE">ADMIN_DELETE</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Target Resource</label>
                <input
                  type="text"
                  required
                  value={ingestForm.resource}
                  onChange={(e) => setIngestForm({ ...ingestForm, resource: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Classification</label>
                  <select
                    value={ingestForm.resource_classification}
                    onChange={(e) => setIngestForm({ ...ingestForm, resource_classification: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                  >
                    <option value="PUBLIC">PUBLIC</option>
                    <option value="INTERNAL">INTERNAL</option>
                    <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                    <option value="RESTRICTED_HIGH_VALUE">RESTRICTED_HIGH_VALUE</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Access Decision</label>
                  <select
                    value={ingestForm.access_decision}
                    onChange={(e) => setIngestForm({ ...ingestForm, access_decision: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                  >
                    <option value="ALLOW">ALLOW</option>
                    <option value="DENY">DENY</option>
                  </select>
                </div>
              </div>

              {ingestStatus && (
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300">
                  {ingestStatus}
                </div>
              )}

              <div className="flex items-center justify-end space-x-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowIngestModal(false)}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={ingesting}
                  className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs"
                >
                  {ingesting ? 'Evaluating Event...' : 'Submit Event to Engine'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Inspect Event Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h2 className="text-sm font-bold text-slate-100 font-mono">
                Event Payload: {selectedEvent.id}
              </h2>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-500">Timestamp:</span>
                <span className="text-slate-200">{new Date(selectedEvent.timestamp).toISOString()}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-500">Identity / Role:</span>
                <span className="text-slate-200">{selectedEvent.user_id} ({selectedEvent.user_role})</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-500">Source Network:</span>
                <span className="text-slate-200">{selectedEvent.source_ip}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-500">Target Resource:</span>
                <span className="text-slate-200">{selectedEvent.resource}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/80">
                <span className="text-slate-500">Decision / Auth:</span>
                <span className="text-slate-200">{selectedEvent.access_decision} / {selectedEvent.auth_result}</span>
              </div>
              <div className="space-y-1 pt-2">
                <span className="text-slate-500">Context Metadata (Redacted Telemetry):</span>
                <pre className="p-3 bg-slate-950 rounded border border-slate-800 text-[11px] text-slate-300 overflow-x-auto">
                  {JSON.stringify(selectedEvent.context_metadata, null, 2)}
                </pre>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono"
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
