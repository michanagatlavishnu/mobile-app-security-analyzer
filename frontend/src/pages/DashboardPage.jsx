import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  UploadCloud,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Key,
  Globe,
  Activity,
  History,
  GitCompare,
  TrendingUp,
  Layers,
  ArrowRight,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from 'recharts';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import scanService from '../services/scanService';
import { getRiskScoreColor, getSeverityColor, formatDate } from '../utils/formatters';

export default function DashboardPage() {
  const location = useLocation();
  const [deniedNotice, setDeniedNotice] = useState(location.state?.accessDenied || '');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [dashboardData, setDashboardData] = useState(null);

  const fetchStats = async () => {
    try {
      setLoading(true);
      setError('');
      const data = await scanService.getDashboardStats();
      setDashboardData(data);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load security operations dashboard telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const stats = dashboardData?.stats || {
    totalScans: 0,
    completedScans: 0,
    failedScans: 0,
    avgSecurityScore: null,
    criticalFindings: 0,
    highFindings: 0,
    mediumFindings: 0,
    lowFindings: 0,
    secretsDetected: 0,
    networkFindings: 0,
  };

  const scoreHistory = dashboardData?.scoreHistory || [];
  const topIssues = dashboardData?.topIssues || [];

  // Severity data for chart
  const severityChartData = [
    { name: 'Critical', count: stats.criticalFindings, color: '#ef4444' },
    { name: 'High', count: stats.highFindings, color: '#f97316' },
    { name: 'Medium', count: stats.mediumFindings, color: '#eab308' },
    { name: 'Low', count: stats.lowFindings, color: '#06b6d4' },
  ];

  // Score history formatted for AreaChart
  const historyChartData = scoreHistory.map((s, idx) => ({
    name: s.apkName?.substring(0, 14) || `Scan #${s.id}`,
    score: s.score,
    date: s.date ? new Date(s.date).toLocaleDateString() : `#${s.id}`,
    riskLevel: s.riskLevel,
  }));

  return (
    <div className="space-y-6">
      {deniedNotice && (
        <div className="p-4 bg-red-950/40 border border-red-500/40 rounded-xl flex items-center justify-between text-xs text-red-300 font-mono shadow-lg">
          <div className="flex items-center gap-3">
            <ShieldAlert className="h-5 w-5 text-red-400 shrink-0" />
            <span>{deniedNotice}</span>
          </div>
          <button
            onClick={() => setDeniedNotice('')}
            className="text-slate-400 hover:text-white px-2 py-1 rounded hover:bg-red-900/40 transition-colors"
          >
            ✕
          </button>
        </div>
      )}

      <PageHeader
        title="Security Operations Dashboard"
        description="Unified security posture, vulnerability distributions, score trajectories, and audit telemetry."
        badge={
          <Badge
            label={stats.completedScans > 0 ? 'TELEMETRY ACTIVE' : 'AWAITING AUDIT DATA'}
            variant={stats.completedScans > 0 ? 'success' : 'neutral'}
          />
        }
        actions={
          <div className="flex flex-wrap items-center gap-2.5">
            <Link to="/scans/compare">
              <Button variant="outline" size="sm">
                <GitCompare className="h-4 w-4 mr-1.5" />
                Compare Scans
              </Button>
            </Link>
            <Link to="/scans">
              <Button variant="outline" size="sm">
                <History className="h-4 w-4 mr-1.5" />
                History
              </Button>
            </Link>
            <Link to="/upload">
              <Button variant="primary" size="sm" className="shadow-cyber-glow">
                <UploadCloud className="h-4 w-4 mr-1.5" />
                Upload APK
              </Button>
            </Link>
          </div>
        }
      />

      {loading && <LoadingSpinner message="Aggregating security telemetry and score trajectory..." />}

      {error && <ErrorState title="Dashboard Error" message={error} onRetry={fetchStats} />}

      {!loading && (
        <>
          {/* Key Metrics Cards Grid */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <Card className="border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Total Ingested</span>
                <Layers className="h-4 w-4 text-cyan-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-black font-mono text-slate-100">{stats.totalScans}</span>
                <span className="text-xs font-mono text-slate-400">APKs</span>
              </div>
              <span className="text-[10px] text-slate-500 font-mono mt-1 block">
                {stats.completedScans} completed • {stats.failedScans} failed
              </span>
            </Card>

            <Card className="border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">Avg Security Score</span>
                <Activity className="h-4 w-4 text-cyan-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className={`text-3xl font-black font-mono ${stats.avgSecurityScore !== null ? getRiskScoreColor(stats.avgSecurityScore) : 'text-slate-500'}`}>
                  {stats.avgSecurityScore !== null ? stats.avgSecurityScore : '--'}
                </span>
                <span className="text-xs font-mono text-slate-400">/ 100</span>
              </div>
              <span className="text-[10px] text-slate-500 font-mono mt-1 block">
                Across all verified scans
              </span>
            </Card>

            <Card className="border-red-500/20 bg-red-950/10">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-red-400 uppercase tracking-wider">Critical & High</span>
                <ShieldAlert className="h-4 w-4 text-red-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-black font-mono text-red-400">
                  {stats.criticalFindings + stats.highFindings}
                </span>
                <span className="text-xs font-mono text-red-400/80">findings</span>
              </div>
              <span className="text-[10px] text-red-400/70 font-mono mt-1 block">
                {stats.criticalFindings} Critical • {stats.highFindings} High
              </span>
            </Card>

            <Card className="border-amber-500/20 bg-amber-950/10">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-amber-400 uppercase tracking-wider">Secrets & Network</span>
                <Key className="h-4 w-4 text-amber-400" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-black font-mono text-amber-400">
                  {stats.secretsDetected + stats.networkFindings}
                </span>
                <span className="text-xs font-mono text-amber-400/80">exposures</span>
              </div>
              <span className="text-[10px] text-amber-400/70 font-mono mt-1 block">
                {stats.secretsDetected} Secrets • {stats.networkFindings} Network
              </span>
            </Card>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Score Trajectory Chart */}
            <Card
              title="Security Score History"
              subtitle="Deterministic score trajectory across completed assessments"
              className="lg:col-span-2 border-slate-800"
            >
              {historyChartData.length === 0 ? (
                <div className="h-56 flex flex-col items-center justify-center text-center p-6 text-slate-500 text-xs">
                  <Activity className="h-8 w-8 text-slate-600 mb-2" />
                  <p>No completed scans yet.</p>
                  <p className="text-[11px] text-slate-600 mt-1">Upload and analyze an APK to plot security posture over time.</p>
                </div>
              ) : (
                <div className="h-60 mt-3">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={historyChartData} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                      <defs>
                        <linearGradient id="scoreGlow" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.35} />
                          <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                      <YAxis stroke="#64748b" fontSize={10} domain={[0, 100]} tickLine={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#334155',
                          borderRadius: '8px',
                          fontSize: '11px',
                          color: '#f8fafc',
                        }}
                      />
                      <Area
                        type="monotone"
                        dataKey="score"
                        stroke="#06b6d4"
                        strokeWidth={2.5}
                        fillOpacity={1}
                        fill="url(#scoreGlow)"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Card>

            {/* Severity Distribution Chart */}
            <Card
              title="Severity Distribution"
              subtitle="Aggregate verified vulnerabilities by tier"
              className="border-slate-800"
            >
              <div className="h-60 mt-3">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityChartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                    <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                    <YAxis stroke="#64748b" fontSize={10} tickLine={false} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '8px',
                        fontSize: '11px',
                        color: '#f8fafc',
                      }}
                    />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {severityChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
          </div>

          {/* Top Detected Issues Section */}
          <Card
            title="Most Frequently Detected Security Issues"
            subtitle="Recurring vulnerabilities and misconfigurations across inspected applications"
            className="border-slate-800"
          >
            {topIssues.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500">
                No vulnerabilities recorded yet.
              </div>
            ) : (
              <div className="overflow-x-auto mt-2">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                      <th className="py-2.5 px-3">Security Issue</th>
                      <th className="py-2.5 px-3">Severity</th>
                      <th className="py-2.5 px-3">Classification</th>
                      <th className="py-2.5 px-3">CWE ID</th>
                      <th className="py-2.5 px-3 text-right">Occurrence Count</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {topIssues.map((issue, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/40">
                        <td className="py-2.5 px-3 font-semibold text-slate-100">{issue.title}</td>
                        <td className="py-2.5 px-3">
                          <Badge severity={issue.severity} label={issue.severity} />
                        </td>
                        <td className="py-2.5 px-3 text-slate-400">{issue.category}</td>
                        <td className="py-2.5 px-3 text-cyan-400 font-mono">{issue.cwe || 'N/A'}</td>
                        <td className="py-2.5 px-3 text-right font-bold text-slate-200">
                          {issue.count} app{issue.count !== 1 ? 's' : ''}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
