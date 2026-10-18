'use client';

import React, { useState, useEffect } from 'react';
import {
  Sliders,
  Shield,
  RefreshCw,
  RotateCcw,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Save,
} from 'lucide-react';
import { api } from '@/lib/api';
import { DetectionRuleConfig } from '@/types/sentinelz';
import { useAuth } from '@/context/AuthContext';
import { SeverityBadge } from '@/components/Badge';

export default function SettingsPage() {
  const { activeRole } = useAuth();
  const [rules, setRules] = useState<DetectionRuleConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingRule, setSavingRule] = useState<string | null>(null);
  const [reseeding, setReseeding] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [confirmReseedModal, setConfirmReseedModal] = useState(false);

  const isAdmin = activeRole === 'security_admin';

  const fetchRules = async () => {
    setLoading(true);
    try {
      const data = await api.getDetectionRules();
      setRules(data);
    } catch (err: any) {
      console.warn('Cannot fetch rules:', err.message);
      setRules([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isAdmin) {
      fetchRules();
    } else {
      setLoading(false);
    }
  }, [isAdmin]);

  const handleToggleRule = async (ruleId: string, currentEnabled: boolean) => {
    setSavingRule(ruleId);
    try {
      const updated = await api.updateDetectionRule(ruleId, { is_enabled: !currentEnabled });
      setRules(rules.map((r) => (r.rule_id === ruleId ? updated : r)));
      setMessage(`Rule ${ruleId} status updated to ${!currentEnabled ? 'Enabled' : 'Disabled'}!`);
      setTimeout(() => setMessage(null), 3000);
    } catch (err: any) {
      setMessage(`Rule update failed: ${err.message}`);
    } finally {
      setSavingRule(null);
    }
  };

  const handleUpdateThreshold = async (ruleId: string, threshold: number) => {
    setSavingRule(ruleId);
    try {
      const updated = await api.updateDetectionRule(ruleId, { threshold_count: threshold });
      setRules(rules.map((r) => (r.rule_id === ruleId ? updated : r)));
      setMessage(`Rule ${ruleId} threshold updated to ${threshold}!`);
      setTimeout(() => setMessage(null), 3000);
    } catch (err: any) {
      setMessage(`Threshold update failed: ${err.message}`);
    } finally {
      setSavingRule(null);
    }
  };

  const handleReseed = async () => {
    setReseeding(true);
    setMessage(null);
    try {
      const res = await api.reseedDemo();
      setMessage(`Demo state re-initialized successfully! (${res.events} events, ${res.findings} findings)`);
      setConfirmReseedModal(false);
      setTimeout(() => setMessage(null), 4000);
    } catch (err: any) {
      setMessage(`Reseed failed: ${err.message}`);
    } finally {
      setReseeding(false);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto font-mono text-xs">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-4 border-b border-slate-800 gap-4 font-sans">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center space-x-2">
            <Sliders className="w-5 h-5 text-blue-400" />
            <span>Detection Settings &amp; System Configuration</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Configure sliding-window rule sensitivity, correlation thresholds, and synthetic demo state.
          </p>
        </div>

        {isAdmin && (
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setConfirmReseedModal(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-800 font-semibold transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reseed Demo Database</span>
            </button>
          </div>
        )}
      </div>

      {message && (
        <div className="p-3 rounded bg-slate-900 border border-cyan-800 text-cyan-300 text-xs">
          {message}
        </div>
      )}

      {/* RBAC Notice if Not Admin */}
      {!isAdmin && (
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2 text-xs">
          <div className="flex items-center space-x-2 text-amber-400 font-bold font-sans">
            <Lock className="w-4 h-4" />
            <span>Administrator Access Required</span>
          </div>
          <p className="text-slate-400 leading-relaxed">
            Modifying detection engine rule thresholds and re-seeding the synthetic database requires the <strong className="text-rose-400">security_admin</strong> role.
            You are currently authenticated as <strong>{activeRole}</strong>. Use the sidebar persona switcher to activate administrator credentials.
          </p>
        </div>
      )}

      {/* Detection Rules Table */}
      <div className="p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between font-sans">
          <div>
            <h2 className="text-sm font-bold text-slate-200">Explainable Threat Detection Rule Configurations</h2>
            <p className="text-[11px] text-slate-400 font-mono">
              Adjustable sliding-window count thresholds and base severity weights
            </p>
          </div>

          {isAdmin && (
            <button
              onClick={fetchRules}
              className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 rounded transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          )}
        </div>

        {isAdmin ? (
          <div className="overflow-x-auto rounded border border-slate-800 bg-slate-950/60">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[10px] uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-4">Rule Name / ID</th>
                  <th className="py-2.5 px-4">Severity</th>
                  <th className="py-2.5 px-4">Window (Sec)</th>
                  <th className="py-2.5 px-4">Threshold Count</th>
                  <th className="py-2.5 px-4 text-center">Status</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {rules.map((r) => (
                  <tr key={r.rule_id} className="hover:bg-slate-900/50">
                    <td className="py-2.5 px-4">
                      <div className="font-bold text-slate-200">{r.name}</div>
                      <div className="text-[10px] text-blue-400">{r.rule_id}</div>
                      <div className="text-[10px] text-slate-500 line-clamp-1 max-w-sm">{r.description}</div>
                    </td>
                    <td className="py-2.5 px-4">
                      <SeverityBadge severity={r.severity} size="sm" />
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">{r.window_seconds}s</td>
                    <td className="py-2.5 px-4">
                      <input
                        type="number"
                        min="1"
                        max="50"
                        defaultValue={r.threshold_count}
                        onBlur={(e) => handleUpdateThreshold(r.rule_id, parseInt(e.target.value) || r.threshold_count)}
                        className="w-16 bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none focus:border-blue-500"
                      />
                    </td>
                    <td className="py-2.5 px-4 text-center">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                          r.is_enabled
                            ? 'bg-emerald-950/80 text-emerald-400 border-emerald-800'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}
                      >
                        {r.is_enabled ? 'ENABLED' : 'DISABLED'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => handleToggleRule(r.rule_id, r.is_enabled)}
                        disabled={savingRule === r.rule_id}
                        className={`px-2.5 py-1 rounded text-[11px] transition-colors ${
                          r.is_enabled
                            ? 'bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-800'
                            : 'bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-800'
                        }`}
                      >
                        {r.is_enabled ? 'Disable' : 'Enable'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-8 text-center rounded border border-slate-800 bg-slate-950/40 text-slate-500">
            Rules list view is restricted to Security Administrators.
          </div>
        )}
      </div>

      {/* Confirmation Modal for Reseed */}
      {confirmReseedModal && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4 backdrop-blur-sm">
          <div className="bg-slate-900 border border-rose-800 rounded-lg max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center space-x-2 text-rose-400">
              <AlertTriangle className="w-5 h-5" />
              <h3 className="text-sm font-bold text-slate-100 font-sans">Confirm Demo Reseed</h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              This action will purge current demo findings, synthetic events, and audit records, and re-generate a pristine set of 45+ realistic synthetic telemetry records and threat scenarios.
            </p>
            <div className="flex justify-end space-x-2 pt-3 border-t border-slate-800">
              <button
                onClick={() => setConfirmReseedModal(false)}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
              >
                Cancel
              </button>
              <button
                onClick={handleReseed}
                disabled={reseeding}
                className="px-4 py-1.5 rounded bg-rose-700 hover:bg-rose-600 text-white font-semibold text-xs"
              >
                {reseeding ? 'Reseeding...' : 'Confirm Reseed'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
