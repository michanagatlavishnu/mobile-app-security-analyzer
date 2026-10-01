import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldCheck,
  Users,
  UserCheck,
  UserX,
  Shield,
  UploadCloud,
  Activity,
  CheckCircle2,
  XCircle,
  AlertOctagon,
  AlertTriangle,
  AlertCircle,
  Info,
  Calendar,
  Clock,
  TrendingUp,
  RefreshCw,
  HardDrive,
  ArrowRight,
  UserMinus,
  Sparkles,
  BarChart3,
  Layers,
  FileText,
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
  CartesianGrid,
} from 'recharts';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import adminService from '../services/adminService';
import { formatDate } from '../utils/formatters';

export default function AdminPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [dashboardData, setDashboardData] = useState(null);
  const [regAnalytics, setRegAnalytics] = useState(null);
  const [activityAnalytics, setActivityAnalytics] = useState(null);
  const [activeTab, setActiveTab] = useState('daily'); // 'daily' | 'weekly' | 'monthly'

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError('');
      const [dashRes, regRes, actRes] = await Promise.all([
        adminService.getDashboard(),
        adminService.getRegistrationAnalytics(),
        adminService.getActivityAnalytics(),
      ]);

      setDashboardData(dashRes);
      setRegAnalytics(regRes);
      setActivityAnalytics(actRes);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to retrieve administrative overview metrics.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const cards = dashboardData?.cards || {};
  const regStats = dashboardData?.registrationStats || {};
  const usageStats = dashboardData?.usageStats || {};
  const activityFeeds = dashboardData?.platformActivity || {};

  return (
    <div className="space-y-6">
      <PageHeader
        title="Admin Security Operations Overview"
        description="Global platform telemetry, user governance metrics, vulnerability posture, and audit logs."
        badge={<Badge label="SecOps Admin Active" variant="danger" />}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={fetchDashboardData} disabled={loading}>
              <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
            </Button>
            <Link to="/admin/users">
              <Button variant="primary" size="sm">
                <Users className="h-3.5 w-3.5 mr-1.5" /> Manage Users
              </Button>
            </Link>
          </div>
        }
      />

      {loading && <LoadingSpinner message="Querying administrative metrics and analytics from database..." />}

      {error && <ErrorState title="Telemetry Error" message={error} onRetry={fetchDashboardData} />}

      {!loading && !error && (
        <>
          {/* Section: 14 Required KPI Metrics Cards */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
                Platform Telemetry & Metrics
              </p>
              <span className="text-[11px] font-mono text-cyan-400">14 Core Operational Signals</span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-3">
              {/* Card 1: Total Users */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Total Users</span>
                  <Users className="h-3.5 w-3.5 text-cyan-400" />
                </div>
                <p className="text-2xl font-black text-white font-mono mt-1">{cards.totalUsers ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">Registered accounts</p>
              </Card>

              {/* Card 2: Active Users */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Active Users</span>
                  <UserCheck className="h-3.5 w-3.5 text-emerald-400" />
                </div>
                <p className="text-2xl font-black text-emerald-400 font-mono mt-1">{cards.activeUsers ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">Enabled status</p>
              </Card>

              {/* Card 3: Disabled Users */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Disabled Users</span>
                  <UserX className="h-3.5 w-3.5 text-red-400" />
                </div>
                <p className="text-2xl font-black text-red-400 font-mono mt-1">{cards.disabledUsers ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">Locked accounts</p>
              </Card>

              {/* Card 4: Admin Users */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Admin Users</span>
                  <ShieldCheck className="h-3.5 w-3.5 text-purple-400" />
                </div>
                <p className="text-2xl font-black text-purple-400 font-mono mt-1">{cards.adminUsers ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">SecOps administrators</p>
              </Card>

              {/* Card 5: Analyst Users */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Analyst Users</span>
                  <Shield className="h-3.5 w-3.5 text-sky-400" />
                </div>
                <p className="text-2xl font-black text-sky-400 font-mono mt-1">{cards.analystUsers ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">Security analysts</p>
              </Card>

              {/* Card 6: Total APKs Uploaded */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Total APKs</span>
                  <UploadCloud className="h-3.5 w-3.5 text-indigo-400" />
                </div>
                <p className="text-2xl font-black text-white font-mono mt-1">{cards.totalApks ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">{cards.storageMb ?? 0} MB stored</p>
              </Card>

              {/* Card 7: Total Scans */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Total Scans</span>
                  <Activity className="h-3.5 w-3.5 text-cyan-400" />
                </div>
                <p className="text-2xl font-black text-cyan-400 font-mono mt-1">{cards.totalScans ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">Executed analyses</p>
              </Card>

              {/* Card 8: Completed Scans */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Completed Scans</span>
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                </div>
                <p className="text-2xl font-black text-emerald-400 font-mono mt-1">{cards.completedScans ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">Fully analyzed</p>
              </Card>

              {/* Card 9: Failed Scans */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Failed Scans</span>
                  <XCircle className="h-3.5 w-3.5 text-red-400" />
                </div>
                <p className="text-2xl font-black text-red-400 font-mono mt-1">{cards.failedScans ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">Errored analyses</p>
              </Card>

              {/* Card 10: Total Vulnerabilities */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Total Findings</span>
                  <AlertOctagon className="h-3.5 w-3.5 text-amber-400" />
                </div>
                <p className="text-2xl font-black text-amber-400 font-mono mt-1">{cards.totalVulnerabilities ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">Across all scans</p>
              </Card>

              {/* Card 11: Critical Findings */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Critical</span>
                  <AlertOctagon className="h-3.5 w-3.5 text-red-500" />
                </div>
                <p className="text-2xl font-black text-red-500 font-mono mt-1">{cards.criticalFindings ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">CVSS Critical</p>
              </Card>

              {/* Card 12: High Findings */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">High</span>
                  <AlertTriangle className="h-3.5 w-3.5 text-orange-400" />
                </div>
                <p className="text-2xl font-black text-orange-400 font-mono mt-1">{cards.highFindings ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">CVSS High</p>
              </Card>

              {/* Card 13: Medium Findings */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Medium</span>
                  <AlertCircle className="h-3.5 w-3.5 text-amber-400" />
                </div>
                <p className="text-2xl font-black text-amber-400 font-mono mt-1">{cards.mediumFindings ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">CVSS Medium</p>
              </Card>

              {/* Card 14: Low Findings */}
              <Card className="border-slate-800 p-3 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-slate-400">Low</span>
                  <Info className="h-3.5 w-3.5 text-blue-400" />
                </div>
                <p className="text-2xl font-black text-blue-400 font-mono mt-1">{cards.lowFindings ?? 0}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">CVSS Low</p>
              </Card>
            </div>
          </div>

          {/* Section: Registration & Usage Statistics Aggregates */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Registration Statistics Card */}
            <Card title="Registration Velocity" subtitle="User account growth calculated across active intervals">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-1">
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-center">
                  <p className="text-[10px] font-mono uppercase text-slate-400">Today</p>
                  <p className="text-xl font-bold font-mono text-cyan-400 mt-1">{regStats.today ?? 0}</p>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-center">
                  <p className="text-[10px] font-mono uppercase text-slate-400">This Week</p>
                  <p className="text-xl font-bold font-mono text-sky-400 mt-1">{regStats.thisWeek ?? 0}</p>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-center">
                  <p className="text-[10px] font-mono uppercase text-slate-400">This Month</p>
                  <p className="text-xl font-bold font-mono text-indigo-400 mt-1">{regStats.thisMonth ?? 0}</p>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-center">
                  <p className="text-[10px] font-mono uppercase text-slate-400">Last 30 Days</p>
                  <p className="text-xl font-bold font-mono text-purple-400 mt-1">{regStats.last30Days ?? 0}</p>
                </div>
              </div>
            </Card>

            {/* Usage Statistics Card */}
            <Card title="Platform Engagement" subtitle="Real database-tracked analyst utilization metrics">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mt-1">
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <p className="text-[10px] font-mono uppercase text-slate-400">Uploaded APKs</p>
                  <p className="text-xl font-bold font-mono text-emerald-400 mt-1">{usageStats.usersWithApkUploads ?? 0}</p>
                  <p className="text-[9px] text-slate-500 font-mono mt-0.5">Users who uploaded</p>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <p className="text-[10px] font-mono uppercase text-slate-400">Completed Scans</p>
                  <p className="text-xl font-bold font-mono text-cyan-400 mt-1">{usageStats.usersWithCompletedScans ?? 0}</p>
                  <p className="text-[9px] text-slate-500 font-mono mt-0.5">Users who scanned</p>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 col-span-2 sm:col-span-1">
                  <p className="text-[10px] font-mono uppercase text-slate-400">Scans Today</p>
                  <p className="text-xl font-bold font-mono text-amber-400 mt-1">{usageStats.scansToday ?? 0}</p>
                  <p className="text-[9px] text-slate-500 font-mono mt-0.5">{usageStats.scansThisWeek ?? 0} this week</p>
                </div>
              </div>
            </Card>
          </div>

          {/* Section: Registration Growth Charts (Phase 8) */}
          <Card
            title="User Registration Trends"
            subtitle="Verified historical onboarding trajectory from database records"
            actions={
              <div className="flex items-center gap-1.5 p-1 bg-slate-900 border border-slate-800 rounded-lg">
                <button
                  onClick={() => setActiveTab('daily')}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                    activeTab === 'daily' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Daily (30d)
                </button>
                <button
                  onClick={() => setActiveTab('weekly')}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                    activeTab === 'weekly' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Weekly (12w)
                </button>
                <button
                  onClick={() => setActiveTab('monthly')}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                    activeTab === 'monthly' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Monthly (12m)
                </button>
              </div>
            }
          >
            <div className="h-64 w-full mt-2">
              {activeTab === 'daily' && (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={regAnalytics?.daily || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="regGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize: 10 }} tickFormatter={(d) => d.slice(5)} />
                    <YAxis stroke="#64748b" tick={{ fontSize: 10 }} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace' }}
                      labelStyle={{ color: '#06b6d4' }}
                    />
                    <Area type="monotone" dataKey="count" name="New Users" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#regGrad)" />
                  </AreaChart>
                </ResponsiveContainer>
              )}

              {activeTab === 'weekly' && (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={regAnalytics?.weekly || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="label" stroke="#64748b" tick={{ fontSize: 10 }} />
                    <YAxis stroke="#64748b" tick={{ fontSize: 10 }} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace' }}
                      labelStyle={{ color: '#38bdf8' }}
                    />
                    <Bar dataKey="count" name="Registrations" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}

              {activeTab === 'monthly' && (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={regAnalytics?.monthly || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="month" stroke="#64748b" tick={{ fontSize: 10 }} />
                    <YAxis stroke="#64748b" tick={{ fontSize: 10 }} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace' }}
                      labelStyle={{ color: '#818cf8' }}
                    />
                    <Bar dataKey="count" name="Registrations" fill="#818cf8" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </Card>

          {/* Section: Activity Analytics & Top Platform Users (Phase 9) */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Active Users Breakdown */}
            <Card title="Active Operator Footprint" subtitle="Evidence-based activity metrics">
              <div className="space-y-3 mt-2">
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span className="text-xs font-mono text-slate-300">Active Today</span>
                  </div>
                  <span className="text-base font-bold font-mono text-emerald-400">{activityAnalytics?.activity?.activeToday ?? 0}</span>
                </div>

                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                    <span className="text-xs font-mono text-slate-300">Active This Week</span>
                  </div>
                  <span className="text-base font-bold font-mono text-cyan-400">{activityAnalytics?.activity?.activeThisWeek ?? 0}</span>
                </div>

                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-sky-400"></span>
                    <span className="text-xs font-mono text-slate-300">Active This Month</span>
                  </div>
                  <span className="text-base font-bold font-mono text-sky-400">{activityAnalytics?.activity?.activeThisMonth ?? 0}</span>
                </div>

                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-slate-500"></span>
                    <span className="text-xs font-mono text-slate-400">Never Scanned/Uploaded</span>
                  </div>
                  <span className="text-base font-bold font-mono text-slate-400">{activityAnalytics?.activity?.neverUsedAnalyzer ?? 0}</span>
                </div>
              </div>
            </Card>

            {/* Top Users by Scans */}
            <Card title="Top Operators by Scans" subtitle="Most active scan evaluators">
              <div className="space-y-2 mt-2">
                {(activityAnalytics?.topUsers?.byScans || []).map((u, i) => (
                  <div key={u.id} className="p-2.5 bg-slate-900/40 border border-slate-800/80 rounded-lg flex items-center justify-between text-xs font-mono">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-slate-500 font-bold w-4">#{i + 1}</span>
                      <div className="truncate">
                        <p className="text-slate-200 font-semibold truncate">{u.name}</p>
                        <p className="text-[10px] text-slate-400 truncate">{u.email}</p>
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      <span className="text-cyan-400 font-bold">{u.totalScans}</span>
                      <span className="text-[10px] text-slate-500 block">scans</span>
                    </div>
                  </div>
                ))}
                {(!activityAnalytics?.topUsers?.byScans || activityAnalytics.topUsers.byScans.length === 0) && (
                  <p className="text-xs text-slate-500 font-mono py-4 text-center">No scans recorded yet.</p>
                )}
              </div>
            </Card>

            {/* Top Users by APK Uploads */}
            <Card title="Top Operators by Uploads" subtitle="Highest volume APK contributors">
              <div className="space-y-2 mt-2">
                {(activityAnalytics?.topUsers?.byUploads || []).map((u, i) => (
                  <div key={u.id} className="p-2.5 bg-slate-900/40 border border-slate-800/80 rounded-lg flex items-center justify-between text-xs font-mono">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-slate-500 font-bold w-4">#{i + 1}</span>
                      <div className="truncate">
                        <p className="text-slate-200 font-semibold truncate">{u.name}</p>
                        <p className="text-[10px] text-slate-400 truncate">{u.email}</p>
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      <span className="text-emerald-400 font-bold">{u.totalUploads}</span>
                      <span className="text-[10px] text-slate-500 block">{u.totalMb} MB</span>
                    </div>
                  </div>
                ))}
                {(!activityAnalytics?.topUsers?.byUploads || activityAnalytics.topUsers.byUploads.length === 0) && (
                  <p className="text-xs text-slate-500 font-mono py-4 text-center">No uploads recorded yet.</p>
                )}
              </div>
            </Card>
          </div>

          {/* Section: Platform Live Feeds (Registrations, Scans, Audits) */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Latest Registrations */}
            <Card
              title="Recent Registrations"
              subtitle="Latest operator accounts created"
              actions={
                <Link to="/admin/users" className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center">
                  View All <ArrowRight className="h-3 w-3 ml-1" />
                </Link>
              }
            >
              <div className="space-y-2.5 mt-2">
                {(activityFeeds.latestRegistrations || []).map((u) => (
                  <div key={u.id} className="p-2.5 bg-slate-900/40 border border-slate-800 rounded-lg text-xs font-mono flex items-center justify-between">
                    <div className="min-w-0">
                      <p className="font-semibold text-slate-200 truncate">{u.name}</p>
                      <p className="text-[10px] text-slate-400 truncate">{u.email}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <Badge label={u.role.toUpperCase()} variant={u.role === 'admin' ? 'danger' : 'info'} size="xs" />
                      <span className="text-[10px] text-slate-500 block mt-1">{formatDate(u.created_at)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </Card>

            {/* Latest Scans */}
            <Card
              title="Recent Scan Executions"
              subtitle="Latest APK analyses across platform"
              actions={
                <Link to="/admin/scans" className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center">
                  View All <ArrowRight className="h-3 w-3 ml-1" />
                </Link>
              }
            >
              <div className="space-y-2.5 mt-2">
                {(activityFeeds.latestScans || []).map((s) => (
                  <div key={s.id} className="p-2.5 bg-slate-900/40 border border-slate-800 rounded-lg text-xs font-mono flex items-center justify-between">
                    <div className="min-w-0">
                      <p className="font-semibold text-slate-200 truncate">{s.original_filename}</p>
                      <p className="text-[10px] text-slate-400 truncate">{s.user_name || s.user_email}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <Badge
                        label={s.status.toUpperCase()}
                        variant={s.status === 'completed' ? 'success' : s.status === 'failed' ? 'danger' : 'warning'}
                        size="xs"
                      />
                      <span className="text-[10px] text-slate-500 block mt-1">
                        Score: {s.security_score !== null ? `${s.security_score}/100` : '—'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </Card>

            {/* Latest Audit Events */}
            <Card
              title="Recent Audit Events"
              subtitle="Latest administrative & system operations"
              actions={
                <Link to="/admin/audit-logs" className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center">
                  View All <ArrowRight className="h-3 w-3 ml-1" />
                </Link>
              }
            >
              <div className="space-y-2.5 mt-2">
                {(activityFeeds.latestAuditEvents || []).map((a) => (
                  <div key={a.id} className="p-2.5 bg-slate-900/40 border border-slate-800 rounded-lg text-xs font-mono flex items-center justify-between">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <Badge label={a.action} variant="cyan" size="xs" />
                      </div>
                      <p className="text-[10px] text-slate-400 mt-1 truncate">{a.details || `${a.entity_type || 'System'} #${a.entity_id || ''}`}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <span className="text-[10px] text-slate-500 block">{formatDate(a.created_at)}</span>
                      <span className="text-[9px] text-slate-600 block">{a.ip_address || '127.0.0.1'}</span>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
