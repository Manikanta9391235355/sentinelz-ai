'use client';

import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, UserRole } from '@/types/sentinelz';
import { api } from '@/lib/api';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  activeRole: UserRole;
  switchRole: (role: UserRole) => Promise<void>;
  login: (email: string, pass: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const initAuth = async () => {
    try {
      // First try fetching current user if token exists
      const current = await api.getCurrentUser();
      setUser(current);
    } catch {
      // For immediate zero-friction Datathon evaluation, auto-login as Lead SOC Analyst
      try {
        const res = await api.switchDemoRole('security_analyst');
        setUser(res.user);
      } catch (err) {
        console.warn('Backend not yet reachable on startup. Waiting for connection.', err);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    initAuth();
  }, []);

  const switchRole = async (role: UserRole) => {
    setLoading(true);
    try {
      const res = await api.switchDemoRole(role);
      setUser(res.user);
    } catch (err) {
      console.error('Failed to switch role:', err);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email: string, pass: string) => {
    setLoading(true);
    try {
      const res = await api.login(email, pass);
      setUser(res.user);
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    await api.logout();
    setUser(null);
  };

  const refreshUser = async () => {
    try {
      const current = await api.getCurrentUser();
      setUser(current);
    } catch {
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        activeRole: user?.role || 'viewer',
        switchRole,
        login,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
