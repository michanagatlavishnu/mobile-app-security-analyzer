import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  Lock,
  FileCheck,
  Cpu,
  Layers,
  CheckCircle2,
  ArrowRight,
  Database,
  Terminal,
  Activity,
} from 'lucide-react';
import Button from '../components/Button';
import Card from '../components/Card';
import authService from '../services/authService';

export default function LandingPage() {
  const [apiHealth, setApiHealth] = useState(null);
  const [dbHealth, setDbHealth] = useState(null);

  useEffect(() => {
    // Check backend health on landing mount
    authService.checkHealth()
      .then((data) => setApiHealth(data))
      .catch(() => setApiHealth({ success: false, message: 'Backend unreachable' }));

    authService.checkDbHealth()
      .then((data) => setDbHealth(data))
      .catch(() => setDbHealth({ success: false, database: 'disconnected' }));
  }, []);

  const features = [
    {
      title: 'Manifest & Configuration Audit',
      description: 'Parses AndroidManifest.xml to detect debuggable flags, backup vulnerabilities, cleartext traffic, and exported components.',
      icon: Search,
    },
    {
      title: 'Permission Danger Classification',
      description: 'Categorizes requested permissions by risk tier (SAFE, LOW, MEDIUM, HIGH, CRITICAL) and maps against Android security standards.',
      icon: ShieldAlert,
    },
    {
      title: 'Hardcoded Secret Detection',
      description: 'Scans archive resources and code for API keys, AWS credentials, Firebase URLs, and tokens, presenting masked values.',
      icon: Lock,
    },
    {
      title: 'Network Security Analysis',
      description: 'Detects insecure HTTP endpoints, missing Network Security Configurations, and vulnerable transmission patterns.',
      icon: Activity,
    },
    {
      title: 'Transparent Scoring Engine',
      description: 'Calculates an explainable 0-100 security score derived from weighted vulnerability severities mapped to OWASP Mobile categories.',
      icon: Cpu,
    },
    {
      title: 'Executive PDF Reports',
      description: 'Generates publication-ready PDF security audits with executive summaries, technical findings, and remediation advice.',
      icon: FileCheck,
    },
  ];

  const steps = [
    { step: '01', title: 'Upload APK', desc: 'Securely upload your Android application package with SHA-256 integrity validation.' },
    { step: '02', title: 'Static Decompilation', desc: 'The Python analysis engine inspects binary AXML, DEX structures, and resources.' },
    { step: '03', title: 'Vulnerability Detection', desc: 'Heuristics evaluate permissions, exported components, secrets, and cleartext traffic.' },
    { step: '04', title: 'Audit & Remediation', desc: 'Review interactive dashboard findings, OWASP mappings, and download executive PDF reports.' },
  ];

  return (
    <div className="flex flex-col gap-24 py-12 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
      {/* Hero Section */}
      <section className="text-center pt-8 pb-12 relative">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono mb-6">
          <Terminal className="h-3.5 w-3.5" />
          <span>PRODUCTION-GRADE ANDROID STATIC ANALYSIS</span>
        </div>

        <h1 className="text-4xl sm:text-6xl font-extrabold text-white tracking-tight leading-tight max-w-4xl mx-auto">
          Automated Static Security Audits for <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-sky-500">Android APKs</span>
        </h1>

        <p className="mt-6 text-base sm:text-lg text-slate-400 max-w-2xl mx-auto leading-relaxed">
          Uncover dangerous permissions, unprotected exported components, cleartext HTTP endpoints,
          and exposed secrets in seconds with transparent risk scoring aligned with OWASP Mobile Top 10.
        </p>

        <div className="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link to="/register">
            <Button variant="primary" size="lg" className="w-full sm:w-auto shadow-cyber-glow">
              Get Started Free <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </Link>
          <Link to="/login">
            <Button variant="secondary" size="lg" className="w-full sm:w-auto">
              Sign In to Dashboard
            </Button>
          </Link>
        </div>

        {/* Live System Status Banner */}
        <div className="mt-12 inline-flex flex-wrap items-center justify-center gap-4 p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">API Status:</span>
            {apiHealth?.success ? (
              <span className="text-emerald-400 flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span> Online (v1.0.0)
              </span>
            ) : (
              <span className="text-amber-400">Connecting...</span>
            )}
          </div>
          <span className="text-slate-700">|</span>
          <div className="flex items-center gap-2">
            <span className="text-slate-400">MySQL Database:</span>
            {dbHealth?.database === 'connected' ? (
              <span className="text-emerald-400 flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-emerald-400"></span> Connected
              </span>
            ) : (
              <span className="text-amber-400 flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-amber-400"></span> Service Standby (Phase 2)
              </span>
            )}
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section>
        <div className="text-center mb-12">
          <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">Enterprise Security Capabilities</h2>
          <p className="mt-2 text-sm text-slate-400">Comprehensive static application security testing engineered for modern mobile apps.</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, idx) => {
            const Icon = feature.icon;
            return (
              <Card key={idx} className="hover:border-cyan-500/30 transition-all duration-300">
                <div className="h-10 w-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mb-4">
                  <Icon className="h-5 w-5" />
                </div>
                <h3 className="text-base font-semibold text-slate-100">{feature.title}</h3>
                <p className="mt-2 text-xs text-slate-400 leading-relaxed">{feature.description}</p>
              </Card>
            );
          })}
        </div>
      </section>

      {/* How It Works */}
      <section className="border-t border-slate-800/80 pt-16">
        <div className="text-center mb-12">
          <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">How Analysis Works</h2>
          <p className="mt-2 text-sm text-slate-400">From uploaded binary package to comprehensive remediation guidance in 4 steps.</p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          {steps.map((item, idx) => (
            <div key={idx} className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 relative">
              <span className="font-mono text-xs text-cyan-400 font-bold block mb-2">{item.step}</span>
              <h3 className="text-sm font-semibold text-slate-100 mb-1">{item.title}</h3>
              <p className="text-xs text-slate-400 leading-relaxed">{item.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Tech Stack */}
      <section className="border-t border-slate-800/80 pt-16 text-center">
        <h2 className="text-xl font-bold text-white mb-6">Built With Modern Architecture</h2>
        <div className="flex flex-wrap justify-center items-center gap-4 text-xs font-mono text-slate-400">
          <span className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">React 18</span>
          <span className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">Vite</span>
          <span className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">Node.js + Express</span>
          <span className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">MySQL Database</span>
          <span className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">Python SAST Engine</span>
          <span className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">Tailwind CSS</span>
          <span className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">PDFKit</span>
        </div>
      </section>
    </div>
  );
}
