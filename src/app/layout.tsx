import type { Metadata } from 'next';
import './globals.css';
import { AuthProvider } from '@/context/AuthContext';
import { Sidebar } from '@/components/Sidebar';
import { Navbar } from '@/components/Navbar';

export const metadata: Metadata = {
  title: 'SentinelZ AI — Privacy-First AI Security & Threat Detection Platform',
  description:
    'Intelligence Without Exposure. AI Secured threat analytics, PII redaction shield, server-side RBAC, and IBM LinuxONE architecture readiness.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark h-full bg-slate-950 text-slate-100 antialiased">
      <body className="min-h-full bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-blue-600/30 selection:text-blue-200">
        <AuthProvider>
          <div className="flex min-h-screen">
            <Sidebar />
            <div className="flex-1 ml-64 flex flex-col min-h-screen bg-slate-950">
              <Navbar />
              <main className="flex-1 p-6 overflow-y-auto">{children}</main>
            </div>
          </div>
        </AuthProvider>
      </body>
    </html>
  );
}
