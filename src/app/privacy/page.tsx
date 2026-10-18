'use client';

import React, { useState, useEffect } from 'react';
import {
  Lock,
  ShieldCheck,
  Cpu,
  Sparkles,
  RefreshCw,
  Eye,
  CheckCircle2,
  AlertTriangle,
  Info,
  Copy,
  Check,
} from 'lucide-react';
import { api } from '@/lib/api';
import { PrivacySanitizeResponse, PrivacyAIAnalysisResponse } from '@/types/sentinelz';
import { useAuth } from '@/context/AuthContext';

const SAMPLE_PAYLOADS = [
  {
    title: 'Customer Incident (Mainframe & Email)',
    text: 'Contact user alex@example.com regarding account IBM-ACCT-98F1-44B2 and phone +1 (555) 234-5678 regarding unauthorized transaction from IP 192.168.1.105.',
  },
  {
    title: 'High-Value Mainframe Asset Triage',
    text: 'Mainframe z16 Crypto Express HSM key exchange failure for ledger account ACCT-99120492. Primary contact: sarah.connor@cyberdyne.org, phone 415-555-0199.',
  },
  {
    title: 'Identity & Financial Breach Report',
    text: 'Security audit identified contractor SSN 000-12-3456 accessing customer ledger with payment card 4532-1234-5678-9010 on internal server 10.240.12.8.',
  },
];

export default function PrivacyShieldPage() {
  const { activeRole } = useAuth();
  const [inputText, setInputText] = useState<string>(SAMPLE_PAYLOADS[0].text);
  const [customTerm, setCustomTerm] = useState<string>('');
  const [customPatterns, setCustomPatterns] = useState<string[]>([]);
  const [sanitizing, setSanitizing] = useState<boolean>(false);
  const [analyzingAI, setAnalyzingAI] = useState<boolean>(false);
  const [sanitizeResult, setSanitizeResult] = useState<PrivacySanitizeResponse | null>(null);
  const [aiResult, setAiResult] = useState<PrivacyAIAnalysisResponse | null>(null);
  const [stats, setStats] = useState<any | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const fetchStats = async () => {
    try {
      const data = await api.getPrivacyStats();
      setStats(data);
    } catch (err) {
      console.warn('Could not load privacy stats:', err);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleAddCustomPattern = (e: React.FormEvent) => {
    e.preventDefault();
    if (customTerm.trim() && !customPatterns.includes(customTerm.trim())) {
      setCustomPatterns([...customPatterns, customTerm.trim()]);
      setCustomTerm('');
    }
  };

  const handleRemovePattern = (pattern: string) => {
    setCustomPatterns(customPatterns.filter((p) => p !== pattern));
  };

  const handleSanitizeOnly = async () => {
    setSanitizing(true);
    setAiResult(null);
    try {
      const res = await api.sanitizeText(inputText, customPatterns);
      setSanitizeResult(res);
      fetchStats();
    } catch (err) {
      console.error('Sanitization failed:', err);
    } finally {
      setSanitizing(false);
    }
  };

  const handleRunAIAnalysis = async () => {
    setAnalyzingAI(true);
    try {
      const res = await api.analyzeWithAI(inputText, 'THREAT_SUMMARIZATION', customPatterns);
      setSanitizeResult(res.sanitization_summary);
      setAiResult(res);
      fetchStats();
    } catch (err) {
      console.error('AI Analysis failed:', err);
    } finally {
      setAnalyzingAI(false);
    }
  };

  const handleCopySanitized = () => {
    if (sanitizeResult?.sanitized_text) {
      navigator.clipboard.writeText(sanitizeResult.sanitized_text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-4 border-b border-slate-800 gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center space-x-2">
            <Lock className="w-5 h-5 text-emerald-400" />
            <span>Privacy Shield — Dedicated PII Redaction Boundary</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Strict token-replacement gateway ensuring sensitive data never reaches internal or external AI models.
          </p>
        </div>

        {/* Boundary status badge */}
        <div className="flex items-center space-x-2">
          <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs font-mono">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Boundary: Active (Zero Exposure)</span>
          </div>
        </div>
      </div>

      {/* Aggregate Stats Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800">
          <span className="text-xs font-mono text-slate-400">Total Operations</span>
          <div className="mt-1 text-2xl font-bold font-mono text-slate-100">{stats?.total_operations ?? 0}</div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Shield invocations</p>
        </div>

        <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800">
          <span className="text-xs font-mono text-slate-400">PII Entities Redacted</span>
          <div className="mt-1 text-2xl font-bold font-mono text-emerald-400">
            {stats?.total_entities_redacted ?? 0}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Emails, phones, accounts</p>
        </div>

        <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800">
          <span className="text-xs font-mono text-slate-400">Total Characters Shielded</span>
          <div className="mt-1 text-2xl font-bold font-mono text-blue-400">{stats?.total_chars_shielded ?? 0}</div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Data preserved from models</p>
        </div>

        <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800">
          <span className="text-xs font-mono text-slate-400">Default AI Dispatch Mode</span>
          <div className="mt-1 text-xs font-bold font-mono text-cyan-400">LOCAL_DETERMINISTIC</div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">No external network calls</p>
        </div>
      </div>

      {/* Privacy Guarantee & Limits Notice */}
      <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1.5 text-xs font-mono">
        <div className="flex items-center space-x-2 text-slate-200 font-semibold">
          <Info className="w-4 h-4 text-cyan-400" />
          <span>Privacy Engineering Design &amp; Documented Recognizer Limits</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          SentinelZ AI applies non-overlapping typed replacement masks to syntactic identifiers (RFC-compliant emails, international and US phone numbers, IBM Mainframe Account numbers <code className="bg-slate-950 px-1 py-0.5 rounded text-slate-300">IBM-ACCT-XXXX-XXXX</code>, standard account tokens, SSNs, and IP addresses).
          Pattern recognizers cannot catch implicit or unstructured contextual PII without NLP/LLM layers; therefore, SentinelZ enforces defense-in-depth and strict local execution by default.
        </p>
      </div>

      {/* Main Interactive Sanitizer Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Input Payload Area */}
        <div className="p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-200">Raw Input Text (Unsanitized)</h2>
            <span className="text-[11px] font-mono text-slate-500">{inputText.length} characters</span>
          </div>

          {/* Quick Scenario Fillers */}
          <div className="space-y-1.5">
            <span className="text-[11px] font-mono text-slate-400">Load Datathon Test Scenarios:</span>
            <div className="flex flex-wrap gap-1.5">
              {SAMPLE_PAYLOADS.map((sample, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setInputText(sample.text);
                    setSanitizeResult(null);
                    setAiResult(null);
                  }}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-mono border border-slate-700 transition-colors"
                >
                  {sample.title}
                </button>
              ))}
            </div>
          </div>

          {/* Input Textarea */}
          <textarea
            rows={7}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Paste security log, support ticket, or telemetry payload here..."
            className="w-full p-3 bg-slate-950 border border-slate-800 rounded font-mono text-xs text-slate-200 focus:outline-none focus:border-blue-500 leading-relaxed"
          />

          {/* Custom Keywords / Recognizers */}
          <div className="space-y-2 pt-2 border-t border-slate-800/80">
            <label className="block text-xs font-mono text-slate-400">
              Configurable Sensitive Keywords / Project Names:
            </label>
            <form onSubmit={handleAddCustomPattern} className="flex gap-2">
              <input
                type="text"
                placeholder="e.g. PROJECT_ZEUS or SECRET_KEY"
                value={customTerm}
                onChange={(e) => setCustomTerm(e.target.value)}
                className="flex-1 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-blue-500"
              />
              <button
                type="submit"
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono transition-colors"
              >
                Add Token
              </button>
            </form>

            {customPatterns.length > 0 && (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {customPatterns.map((pat) => (
                  <span
                    key={pat}
                    className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-purple-950 text-purple-300 border border-purple-800"
                  >
                    <span>{pat}</span>
                    <button
                      onClick={() => handleRemovePattern(pat)}
                      className="ml-1.5 text-purple-400 hover:text-purple-200"
                    >
                      &times;
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex items-center space-x-3 pt-3 border-t border-slate-800">
            <button
              onClick={handleSanitizeOnly}
              disabled={sanitizing || analyzingAI || !inputText.trim()}
              className="flex-1 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold transition-colors flex items-center justify-center space-x-2"
            >
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              <span>{sanitizing ? 'Redacting...' : 'Preview Redaction Only'}</span>
            </button>

            <button
              onClick={handleRunAIAnalysis}
              disabled={sanitizing || analyzingAI || !inputText.trim()}
              className="flex-1 py-2 rounded bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-mono font-semibold transition-colors flex items-center justify-center space-x-2 shadow-lg shadow-emerald-950/50"
            >
              <Sparkles className="w-3.5 h-3.5 text-white" />
              <span>{analyzingAI ? 'Sanitizing & Analyzing...' : 'Shield & Analyze (AI Safe)'}</span>
            </button>
          </div>
        </div>

        {/* Right: Sanitized Transformation & Analysis Preview */}
        <div className="p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Sanitized Output (Safe for AI Processing)</span>
            </h2>

            {sanitizeResult && (
              <button
                onClick={handleCopySanitized}
                className="flex items-center space-x-1 text-xs font-mono text-slate-400 hover:text-slate-200 transition-colors"
                title="Copy sanitized text"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            )}
          </div>

          {sanitizeResult ? (
            <div className="space-y-4">
              {/* Transformation Metadata Card */}
              <div className="grid grid-cols-3 gap-2 p-3 rounded bg-slate-950 border border-slate-800 text-xs font-mono">
                <div>
                  <span className="text-slate-500 block text-[10px]">Redacted Items:</span>
                  <span className="text-emerald-400 font-bold text-base">
                    {sanitizeResult.redacted_items_count}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Processing Latency:</span>
                  <span className="text-slate-200 font-semibold">{sanitizeResult.execution_time_ms} ms</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Boundary Status:</span>
                  <span className="text-emerald-400 font-semibold">SECURED</span>
                </div>
              </div>

              {/* Detected Entities Breakdown */}
              {Object.keys(sanitizeResult.detected_entities_summary).length > 0 && (
                <div className="space-y-1">
                  <span className="text-[11px] font-mono text-slate-400">Shielded Entity Classes:</span>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(sanitizeResult.detected_entities_summary).map(([entity, count]) => (
                      <span
                        key={entity}
                        className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-950/80 text-blue-300 border border-blue-800"
                      >
                        {entity}: {count}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Sanitized Text Display */}
              <div className="space-y-1">
                <span className="text-[11px] font-mono text-slate-400">Sanitized Text (Typed Placeholders):</span>
                <pre className="p-3 bg-slate-950 rounded border border-slate-800 text-xs font-mono text-emerald-300 whitespace-pre-wrap leading-relaxed max-h-48 overflow-y-auto">
                  {sanitizeResult.sanitized_text}
                </pre>
              </div>

              {/* AI Inference Output (if triggered) */}
              {aiResult && (
                <div className="p-4 rounded-md bg-slate-950 border border-cyan-900/60 space-y-2 pt-3">
                  <div className="flex items-center justify-between text-xs font-mono border-b border-slate-800 pb-2">
                    <span className="font-semibold text-cyan-300 flex items-center space-x-1.5">
                      <Cpu className="w-4 h-4 text-cyan-400" />
                      <span>{aiResult.ai_provider}</span>
                    </span>
                    <span className="text-slate-500 text-[10px]">Model: {aiResult.model_name}</span>
                  </div>

                  <div className="text-xs font-mono text-slate-200 whitespace-pre-line leading-relaxed">
                    {aiResult.ai_analysis_result}
                  </div>

                  <div className="text-[10px] font-mono text-slate-500 pt-2 border-t border-slate-900">
                    {aiResult.disclaimer}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-12 text-center rounded bg-slate-950/50 border border-slate-800/80 text-xs font-mono text-slate-500 space-y-2">
              <Eye className="w-8 h-8 text-slate-600 mx-auto" />
              <p>Submit text or select a datathon scenario to preview the privacy sanitization boundary.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
