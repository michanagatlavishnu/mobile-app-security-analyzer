import React from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { Shield, Lock, Terminal } from 'lucide-react';
import Button from '../components/Button';

export default function PublicLayout() {
  const location = useLocation();

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100">
      {/* Top Navigation */}
      <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2.5 group">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 group-hover:border-cyan-400/50 transition-colors">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <span className="font-bold text-base tracking-tight text-white flex items-center gap-1.5">
                SECURE<span className="text-cyan-400">APK</span>
              </span>
              <span className="text-[10px] text-slate-400 block -mt-1 font-mono tracking-wider">
                SECURITY ANALYZER
              </span>
            </div>
          </Link>

          <nav className="flex items-center gap-3">
            {location.pathname !== '/login' && (
              <Link to="/login">
                <Button variant="ghost" size="sm">
                  Sign In
                </Button>
              </Link>
            )}
            {location.pathname !== '/register' && (
              <Link to="/register">
                <Button variant="primary" size="sm">
                  Register
                </Button>
              </Link>
            )}
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/60 py-6 text-center text-xs text-slate-400">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-cyan-500" />
            <span>Mobile App Security Analyzer &bull; Production Static Analysis Platform</span>
          </div>
          <div>OWASP Mobile Top 10 &bull; CWE Aligned &bull; Enterprise SAST</div>
        </div>
      </footer>
    </div>
  );
}
