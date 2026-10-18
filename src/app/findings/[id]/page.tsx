'use client';

import React, { useState, useEffect, use } from 'react';
import Link from 'next/link';
import {
  AlertTriangle,
  ArrowLeft,
  Clock,
  User,
  Shield,
  FileCheck,
  CheckCircle,
  AlertCircle,
  HelpCircle,
  Save,
  Send,
} from 'lucide-react';
import { api } from '@/lib/api';
import { ThreatFinding, FindingStatus } from '@/types/sentinelz';
import { SeverityBadge, StatusBadge } from '@/components/Badge';
import { useAuth } from '@/context/AuthContext';

export default function FindingDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { activeRole, user } = useAuth();
  const [finding, setFinding] = useState<ThreatFinding | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Status mutation state
  const [newStatus, setNewStatus] = useState<FindingStatus>('OPEN');
  const [resolutionNotes, setResolutionNotes] = useState<string>('');
  const [savingStatus, setSavingStatus] = useState<boolean>(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  const fetchFinding = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getFindingById(id);
      setFinding(data);
      setNewStatus(data.status);
      setResolutionNotes(data.resolution_notes || '');
    } catch (err: any) {
      setError(err.message || 'Finding details could not be loaded.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFinding();
  }, [id]);

  const handleStatusUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingStatus(true);
    setSaveMessage(null);
    try {
      const updated = await api.updateFindingStatus(id, newStatus, resolutionNotes);
      setFinding(updated);
      setSaveMessage('Status updated successfully and recorded in audit trail!');
      setTimeout(() => setSaveMessage(null), 3000);
    } catch (err: any) {
      setSaveMessage(`Update failed: ${err.message}`);
    } finally {
      setSavingStatus(false);
    }
  };

  const canMutate = activeRole === 'security_admin' || activeRole === 'security_analyst';

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] space-y-2 text-xs font-mono text-slate-400">
        <p>Loading threat finding {id}...</p>
      </div>
    );
  }

  if (error || !finding) {
    return (
      <div className="p-6 rounded-lg bg-red-950/40 border border-red-800 text-red-200 max-w-xl mx-auto my-12 space-y-3 font-mono text-xs">
        <h2 className="text-sm font-bold text-red-300">Access Denied or Not Found</h2>
        <p>{error || `Finding ${id} could not be located.`}</p>
        <Link href="/findings" className="inline-block text-blue-400 underline">
          &larr; Return to Findings List
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Back button */}
      <div>
        <Link
          href="/findings"
          className="inline-flex items-center space-x-1.5 text-xs font-mono text-slate-400 hover:text-slate-200 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Findings</span>
        </Link>
      </div>

      {/* Main Finding Header Card */}
      <div className="p-6 rounded-lg bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div className="space-y-1.5">
            <div className="flex items-center space-x-2.5">
              <SeverityBadge severity={finding.severity} />
              <h1 className="text-lg font-bold text-slate-100">{finding.title}</h1>
            </div>
            <div className="flex items-center space-x-3 text-xs font-mono text-slate-400">
              <span>Finding ID: <strong className="text-slate-300">{finding.id}</strong></span>
              <span>&bull;</span>
              <span>Rule ID: <span className="text-blue-400">{finding.rule_id}</span></span>
              <span>&bull;</span>
              <span>Generated: {new Date(finding.created_at).toLocaleString()}</span>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <div className="text-right">
              <span className="block text-[10px] font-mono text-slate-400 uppercase">Calculated Risk Score</span>
              <span
                className={`text-2xl font-bold font-mono ${
                  finding.risk_score >= 80 ? 'text-red-400' : finding.risk_score >= 60 ? 'text-amber-400' : 'text-blue-400'
                }`}
              >
                {finding.risk_score} / 100
              </span>
            </div>
            <StatusBadge status={finding.status} />
          </div>
        </div>

        {/* Explainable Reasoning */}
        <div className="space-y-2">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 flex items-center space-x-1.5">
            <HelpCircle className="w-3.5 h-3.5 text-blue-400" />
            <span>Detection Explanation &amp; Correlation Context</span>
          </h2>
          <div className="p-4 rounded-md bg-slate-950 border border-slate-800/80 text-xs text-slate-200 font-mono leading-relaxed">
            {finding.explanation}
          </div>
        </div>

        {/* Identity & Asset Details Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-xs font-mono">
          <div className="p-3 rounded bg-slate-950/60 border border-slate-800 space-y-1">
            <span className="text-slate-500 block">Affected Identity:</span>
            <span className="text-slate-200 font-bold">{finding.affected_identity}</span>
          </div>

          <div className="p-3 rounded bg-slate-950/60 border border-slate-800 space-y-1">
            <span className="text-slate-500 block">Detection Method:</span>
            <span className="text-slate-200 font-semibold">{finding.detection_method}</span>
          </div>

          <div className="p-3 rounded bg-slate-950/60 border border-slate-800 space-y-1">
            <span className="text-slate-500 block">Related Telemetry Events:</span>
            <span className="text-blue-400 font-semibold">{finding.related_event_ids?.length || 0} events correlated</span>
          </div>
        </div>
      </div>

      {/* Recommended Investigation Steps */}
      <div className="p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-3">
        <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
          <FileCheck className="w-4 h-4 text-emerald-400" />
          <span>Recommended Non-Destructive Next Steps</span>
        </h2>
        <p className="text-[11px] text-slate-400 font-mono">
          SentinelZ AI recommends human-in-the-loop investigation actions instead of performing irreversible automatic blocks.
        </p>
        <ul className="space-y-2 pt-1">
          {finding.recommended_steps?.map((step, idx) => (
            <li
              key={idx}
              className="flex items-start space-x-2.5 p-2.5 rounded bg-slate-950/70 border border-slate-800/80 text-xs font-mono text-slate-300"
            >
              <span className="w-5 h-5 rounded-full bg-blue-950 text-blue-400 border border-blue-800/80 flex items-center justify-center shrink-0 text-[10px] font-bold">
                {idx + 1}
              </span>
              <span>{step}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Correlated Evidence & Event IDs */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-3">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
            Observed Evidence Payload
          </h2>
          <pre className="p-3 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-60">
            {JSON.stringify(finding.evidence, null, 2)}
          </pre>
        </div>

        {/* Analyst Investigation Workflow & Status Update */}
        <div className="p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-4">
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span>Analyst Investigation Disposition</span>
          </h2>

          {canMutate ? (
            <form onSubmit={handleStatusUpdate} className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Investigation Status</label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value as FindingStatus)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none"
                >
                  <option value="OPEN">OPEN (Requires Analysis)</option>
                  <option value="INVESTIGATING">INVESTIGATING (Triage in Progress)</option>
                  <option value="RESOLVED">RESOLVED (Mitigated / Legitimate)</option>
                  <option value="FALSE_POSITIVE">FALSE_POSITIVE (Authorized Deviation)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Resolution &amp; Triage Notes</label>
                <textarea
                  rows={3}
                  value={resolutionNotes}
                  onChange={(e) => setResolutionNotes(e.target.value)}
                  placeholder="Record justification, supervisor confirmation, or investigation steps..."
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 focus:outline-none placeholder-slate-600"
                />
              </div>

              {saveMessage && (
                <div className="p-2.5 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-xs">
                  {saveMessage}
                </div>
              )}

              <button
                type="submit"
                disabled={savingStatus}
                className="w-full py-2 bg-blue-600 hover:bg-blue-500 text-white rounded font-semibold transition-colors flex items-center justify-center space-x-2"
              >
                <Save className="w-4 h-4" />
                <span>{savingStatus ? 'Recording in Audit Log...' : 'Commit Status Disposition'}</span>
              </button>
            </form>
          ) : (
            <div className="p-4 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-400 space-y-2">
              <AlertCircle className="w-4 h-4 text-amber-400" />
              <p className="font-semibold text-slate-200">Read-Only View (Viewer Role)</p>
              <p>
                Status mutations and triage disposition updates require <strong>Security Analyst</strong> or <strong>Security Administrator</strong> privileges.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
