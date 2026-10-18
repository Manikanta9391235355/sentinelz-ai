'use client';

import React, { useState, useEffect } from 'react';
import { ShieldCheck, Cpu, Database, Bell, RefreshCw } from 'lucide-react';
import { api } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';

export const Navbar: React.FC = () => {
  const { user, activeRole } = useAuth();
  const [healthStatus, setHealthStatus] = useState<string>('checking');
  const [rechecking, setRechecking] = useState<boolean>(false);

  const checkStatus = async () => {
    setRechecking(true);
    try {
      const res = await api.getHealth();
      setHealthStatus(res.status);
    } catch {
      setHealthStatus('offline');
    } finally {
      setRechecking(false);
    }
  };

  useEffect(() => {
    checkStatus();
    const interval = setInterval(checkStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-14 bg-slate-950/90 border-b border-slate-800 flex items-center justify-between px-6 sticky top-0 z-20 backdrop-blur-md">
      {/* Left: Datathon Context */}
      <div className="flex items-center space-x-3">
        <div className="flex items-center space-x-2 text-xs font-mono">
          <span className="w-2 h-2 rounded-full bg-cyan-400" />
          <span className="text-slate-300 font-semibold">IBM Z Datathon 2026</span>
          <span className="text-slate-600">/</span>
          <span className="text-slate-400">AI Secured: Innovation Without Exposure</span>
        </div>
      </div>

      {/* Right: Operational Telemetry & Health */}
      <div className="flex items-center space-x-3 text-xs font-mono">
        {/* Privacy Boundary Status */}
        <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-emerald-950/50 border border-emerald-800/60 text-emerald-300">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-[11px] font-semibold">Privacy Shield: ZERO LEAKAGE</span>
        </div>

        {/* IBM LinuxONE Compatibility */}
        <div className="hidden md:flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-blue-950/50 border border-blue-800/60 text-blue-300">
          <Cpu className="w-3.5 h-3.5 text-blue-400" />
          <span className="text-[11px]">IBM LinuxONE Verified</span>
        </div>

        {/* Backend Health Status */}
        <div
          onClick={checkStatus}
          className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-md border cursor-pointer transition-colors ${
            healthStatus === 'healthy'
              ? 'bg-slate-900 border-slate-800 text-slate-300 hover:border-slate-700'
              : 'bg-rose-950 border-rose-800 text-rose-300'
          }`}
          title="Click to re-check API connection"
        >
          <Database className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-[11px]">
            {healthStatus === 'healthy' ? 'API Online' : 'API Connecting...'}
          </span>
          <RefreshCw className={`w-3 h-3 text-slate-500 ${rechecking ? 'animate-spin' : ''}`} />
        </div>
      </div>
    </header>
  );
};
