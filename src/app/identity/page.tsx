'use client';

import React, { useState, useEffect } from 'react';
import {
  Users,
  Shield,
  Key,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Lock,
  UserCheck,
} from 'lucide-react';
import { api } from '@/lib/api';
import { User, UserRole } from '@/types/sentinelz';
import { useAuth } from '@/context/AuthContext';

const PERMISSION_MATRIX = [
  { action: 'View Aggregate Dashboard Metrics', viewer: true, analyst: true, admin: true },
  { action: 'Inspect Platform Health & Architecture', viewer: true, analyst: true, admin: true },
  { action: 'View Security Event Telemetry', viewer: false, analyst: true, admin: true },
  { action: 'Ingest New Security Events', viewer: false, analyst: true, admin: true },
  { action: 'Inspect Explainable Threat Findings', viewer: false, analyst: true, admin: true },
  { action: 'Investigate & Update Alert Statuses', viewer: false, analyst: true, admin: true },
  { action: 'Submit Payloads to Privacy Shield', viewer: false, analyst: true, admin: true },
  { action: 'Inspect Append-Only Audit Trail', viewer: false, analyst: true, admin: true },
  { action: 'Manage User Accounts & Roles', viewer: false, analyst: false, admin: true },
  { action: 'Modify Detection Rule Sensitivity', viewer: false, analyst: false, admin: true },
  { action: 'Trigger Database Demo Re-Seed', viewer: false, analyst: false, admin: true },
];

export default function IdentityAccessPage() {
  const { activeRole, switchRole, user: currentUser } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [updatingUser, setUpdatingUser] = useState<number | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const data = await api.getUsers();
      setUsers(data);
    } catch (err: any) {
      console.warn('Cannot fetch user list under current role permissions:', err.message);
      setUsers([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, [activeRole]);

  const handleRoleChange = async (userId: number, newRole: UserRole) => {
    setUpdatingUser(userId);
    setActionMessage(null);
    try {
      const updated = await api.updateUserRole(userId, newRole);
      setUsers(users.map((u) => (u.id === userId ? updated : u)));
      setActionMessage(`Role for ${updated.email} updated to ${newRole}!`);
      setTimeout(() => setActionMessage(null), 3000);
    } catch (err: any) {
      setActionMessage(`Role update denied by server: ${err.message}`);
    } finally {
      setUpdatingUser(null);
    }
  };

  const isAdmin = activeRole === 'security_admin';

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-4 border-b border-slate-800 gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center space-x-2">
            <Users className="w-5 h-5 text-blue-400" />
            <span>Identity &amp; Role-Based Access Control (RBAC)</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Server-enforced authorization model with least privilege and horizontal/vertical escalation protection.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-slate-400">
            Active Persona: <strong className="text-cyan-400 uppercase">{activeRole}</strong>
          </span>
        </div>
      </div>

      {/* RBAC Notice if Not Admin */}
      {!isAdmin && (
        <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-900/40 text-xs font-mono text-amber-200 flex items-start space-x-3">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-semibold text-amber-300">Server-Side Authorization Boundary Active</span>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              You are currently authenticated as <strong>{activeRole}</strong>.
              User identity administration (<code className="text-slate-300">/api/users</code>) and role reassignment require the <strong className="text-rose-400">security_admin</strong> role.
              Use the sidebar switcher to test administrator permissions live.
            </p>
          </div>
        </div>
      )}

      {/* Interactive Persona Switching Showcase */}
      <div className="p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-3">
        <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
          <Key className="w-4 h-4 text-cyan-400" />
          <span>Datathon Persona Quick-Switch</span>
        </h2>
        <p className="text-[11px] font-mono text-slate-400">
          Switch between verified demo accounts to observe backend enforcement in real-time:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
          {/* Admin Card */}
          <div
            onClick={() => switchRole('security_admin')}
            className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
              activeRole === 'security_admin'
                ? 'bg-rose-950/40 border-rose-600 ring-1 ring-rose-500'
                : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="font-bold text-rose-300">Security Administrator</span>
              {activeRole === 'security_admin' && (
                <span className="px-1.5 py-0.5 rounded bg-rose-900 text-rose-200 text-[10px]">ACTIVE</span>
              )}
            </div>
            <p className="text-[11px] text-slate-300 font-mono mt-1">admin@sentinelz.local</p>
            <p className="text-[10px] text-slate-500 font-mono mt-1">
              Full user management, detection configuration, and system re-seeding rights.
            </p>
          </div>

          {/* Analyst Card */}
          <div
            onClick={() => switchRole('security_analyst')}
            className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
              activeRole === 'security_analyst'
                ? 'bg-cyan-950/40 border-cyan-600 ring-1 ring-cyan-500'
                : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="font-bold text-cyan-300">Security Analyst</span>
              {activeRole === 'security_analyst' && (
                <span className="px-1.5 py-0.5 rounded bg-cyan-900 text-cyan-200 text-[10px]">ACTIVE</span>
              )}
            </div>
            <p className="text-[11px] text-slate-300 font-mono mt-1">analyst@sentinelz.local</p>
            <p className="text-[10px] text-slate-500 font-mono mt-1">
              Event telemetry review, alert investigation, status triage, and privacy shield.
            </p>
          </div>

          {/* Viewer Card */}
          <div
            onClick={() => switchRole('viewer')}
            className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
              activeRole === 'viewer'
                ? 'bg-slate-800/80 border-slate-500 ring-1 ring-slate-400'
                : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="font-bold text-slate-300">Compliance Viewer</span>
              {activeRole === 'viewer' && (
                <span className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-200 text-[10px]">ACTIVE</span>
              )}
            </div>
            <p className="text-[11px] text-slate-300 font-mono mt-1">viewer@sentinelz.local</p>
            <p className="text-[10px] text-slate-500 font-mono mt-1">
              Read-only aggregate dashboard metrics. Denied ingestion and administrative actions.
            </p>
          </div>
        </div>
      </div>

      {/* Users List & Role Modification (Admin Only) */}
      <div className="p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">System Identities &amp; Role Assignments</h2>
            <p className="text-[11px] text-slate-400 font-mono">
              Server-enforced role assignments (Restricted to Security Administrators)
            </p>
          </div>

          {isAdmin && (
            <button
              onClick={fetchUsers}
              className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 rounded transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          )}
        </div>

        {actionMessage && (
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300">
            {actionMessage}
          </div>
        )}

        {isAdmin ? (
          <div className="overflow-x-auto rounded border border-slate-800 bg-slate-950/60">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[10px] uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-4">User ID</th>
                  <th className="py-2.5 px-4">Full Name</th>
                  <th className="py-2.5 px-4">Email</th>
                  <th className="py-2.5 px-4">Current Role</th>
                  <th className="py-2.5 px-4">Account Status</th>
                  <th className="py-2.5 px-4 text-right">Assign Role</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-900/50">
                    <td className="py-2.5 px-4 text-slate-500">#{u.id}</td>
                    <td className="py-2.5 px-4 font-semibold text-slate-200">{u.full_name}</td>
                    <td className="py-2.5 px-4 text-slate-400">{u.email}</td>
                    <td className="py-2.5 px-4">
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded border font-mono ${
                          u.role === 'security_admin'
                            ? 'bg-rose-950 text-rose-300 border-rose-800'
                            : u.role === 'security_analyst'
                            ? 'bg-cyan-950 text-cyan-300 border-cyan-800'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}
                      >
                        {u.role}
                      </span>
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="text-[10px] text-emerald-400 font-mono">ACTIVE</span>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <select
                        value={u.role}
                        disabled={updatingUser === u.id}
                        onChange={(e) => handleRoleChange(u.id, e.target.value as UserRole)}
                        className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none"
                      >
                        <option value="security_admin">security_admin</option>
                        <option value="security_analyst">security_analyst</option>
                        <option value="viewer">viewer</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-8 text-center rounded border border-slate-800 bg-slate-950/40 text-xs font-mono text-slate-500">
            <Lock className="w-6 h-6 mx-auto mb-2 text-slate-600" />
            <span>Identity database access is restricted to Security Administrators. Switch role to manage users.</span>
          </div>
        )}
      </div>

      {/* Comprehensive Permission Matrix */}
      <div className="p-5 rounded-lg bg-slate-900/70 border border-slate-800 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">Server-Side Authorization Permission Matrix</h2>
          <p className="text-[11px] text-slate-400 font-mono">
            Granular access policy enforced via FastAPI dependency injection (<code className="text-blue-300">require_role</code>)
          </p>
        </div>

        <div className="overflow-x-auto rounded border border-slate-800 bg-slate-950/60">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[10px] uppercase tracking-wider">
              <tr>
                <th className="py-2.5 px-4">Operational Capability</th>
                <th className="py-2.5 px-4 text-center">Viewer</th>
                <th className="py-2.5 px-4 text-center">Security Analyst</th>
                <th className="py-2.5 px-4 text-center">Security Admin</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {PERMISSION_MATRIX.map((row, idx) => (
                <tr key={idx} className="hover:bg-slate-900/50">
                  <td className="py-2.5 px-4 text-slate-200">{row.action}</td>
                  <td className="py-2.5 px-4 text-center">
                    {row.viewer ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 mx-auto" />
                    ) : (
                      <XCircle className="w-4 h-4 text-slate-600 mx-auto" />
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-center">
                    {row.analyst ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 mx-auto" />
                    ) : (
                      <XCircle className="w-4 h-4 text-slate-600 mx-auto" />
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-center">
                    {row.admin ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 mx-auto" />
                    ) : (
                      <XCircle className="w-4 h-4 text-slate-600 mx-auto" />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
