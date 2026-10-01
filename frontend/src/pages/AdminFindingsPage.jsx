import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertOctagon,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle2,
  Search,
  Filter,
  ArrowUpDown,
  RefreshCw,
  ExternalLink,
  Shield,
  Layers,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  LineChart,
  Line,
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
import { formatDate, getSeverityColor } from '../utils/formatters';

export default function AdminFindingsPage() {
  const [data, setData] = useState(null);
  const [pagination, setPagination] = useState({ page: 1, limit: 20, total: 0, totalPages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Filters & Search
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('all');
  const [status, setStatus] = useState('all');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState('DESC');

  const fetchFindings = async () => {
    try {
      setLoading(true);
      setError('');
      const res = await adminService.getFindings({
        page: pagination.page,
        limit: pagination.limit,
        severity: severity !== 'all' ? severity : '',
        status: status !== 'all' ? status : '',
        search,
        sortBy,
        sortOrder,
      });

      setData(res);
      if (res.pagination) {
        setPagination(res.pagination);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to retrieve aggregate security findings.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [pagination.page, severity, status, sortBy, sortOrder]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPagination((prev) => ({ ...prev, page: 1 }));
    fetchFindings();
  };

  const overview = data?.overview || {};
  const summary = overview.summary || {};
  const severityData = overview.severityData || [];
  const statusData = overview.statusData || [];
  const categories = overview.categories || [];
  const monthlyTrend = overview.monthlyTrend || [];
  const findings = data?.findings || [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Aggregate Security Findings & Threat Intelligence"
        description="Comprehensive platform-wide vulnerability distribution, threat categories, and resolution lifecycle."
        badge={<Badge label={`${summary.total ?? 0} Total Findings`} variant="danger" />}
        actions={
          <Button variant="outline" size="sm" onClick={fetchFindings} disabled={loading}>
            <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </Button>
        }
      />

      {/* Top 9 Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 xl:grid-cols-9 gap-3">
        <Card className="border-slate-800 p-3">
          <span className="text-[10px] font-mono uppercase text-slate-500">Total Findings</span>
          <p className="text-2xl font-black font-mono text-white mt-1">{summary.total ?? 0}</p>
        </Card>
        <Card className="border-slate-800 p-3">
          <span className="text-[10px] font-mono uppercase text-red-400">Critical</span>
          <p className="text-2xl font-black font-mono text-red-500 mt-1">{summary.critical ?? 0}</p>
        </Card>
        <Card className="border-slate-800 p-3">
          <span className="text-[10px] font-mono uppercase text-orange-400">High</span>
          <p className="text-2xl font-black font-mono text-orange-400 mt-1">{summary.high ?? 0}</p>
        </Card>
        <Card className="border-slate-800 p-3">
          <span className="text-[10px] font-mono uppercase text-amber-400">Medium</span>
          <p className="text-2xl font-black font-mono text-amber-400 mt-1">{summary.medium ?? 0}</p>
        </Card>
        <Card className="border-slate-800 p-3">
          <span className="text-[10px] font-mono uppercase text-blue-400">Low</span>
          <p className="text-2xl font-black font-mono text-blue-400 mt-1">{summary.low ?? 0}</p>
        </Card>
        <Card className="border-slate-800 p-3">
          <span className="text-[10px] font-mono uppercase text-cyan-400">Info</span>
          <p className="text-2xl font-black font-mono text-cyan-400 mt-1">{summary.informational ?? 0}</p>
        </Card>
        <Card className="border-slate-800 p-3">
          <span className="text-[10px] font-mono uppercase text-red-400">Open</span>
          <p className="text-2xl font-black font-mono text-red-400 mt-1">{summary.open ?? 0}</p>
        </Card>
        <Card className="border-slate-800 p-3">
          <span className="text-[10px] font-mono uppercase text-emerald-400">Resolved</span>
          <p className="text-2xl font-black font-mono text-emerald-400 mt-1">{summary.resolved ?? 0}</p>
        </Card>
        <Card className="border-slate-800 p-3">
          <span className="text-[10px] font-mono uppercase text-slate-400">False Pos</span>
          <p className="text-2xl font-black font-mono text-slate-400 mt-1">{summary.falsePositive ?? 0}</p>
        </Card>
      </div>

      {/* 4 Interactive Charts (Phase 12) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Chart 1: Findings by Severity */}
        <Card title="Findings by Severity" subtitle="Global distribution across vulnerability risk tiers">
          <div className="h-56 w-full mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 10 }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 10 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* Chart 2: Findings by Top Categories */}
        <Card title="Findings by Category" subtitle="Most prevalent vulnerability domains">
          <div className="h-56 w-full mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categories.slice(0, 5)} layout="vertical" margin={{ top: 10, right: 10, left: 30, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" stroke="#64748b" tick={{ fontSize: 10 }} allowDecimals={false} />
                <YAxis dataKey="category" type="category" stroke="#64748b" tick={{ fontSize: 10 }} width={80} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace' }}
                />
                <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* Chart 3: Findings Trend Over Time */}
        <Card title="Findings Trend Over Time" subtitle="Monthly rate of newly detected security issues">
          <div className="h-56 w-full mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={monthlyTrend} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="month" stroke="#64748b" tick={{ fontSize: 10 }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 10 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace' }}
                />
                <Line type="monotone" dataKey="total" name="Total Findings" stroke="#f59e0b" strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="criticalHigh" name="Critical / High" stroke="#ef4444" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* Chart 4: Resolved vs Open Findings */}
        <Card title="Lifecycle Resolution Status" subtitle="Open versus resolved & false positive triage">
          <div className="h-56 w-full mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={statusData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 10 }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 10 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px', fontFamily: 'monospace' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {statusData.map((entry, index) => (
                    <Cell key={`cell-status-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      {/* Filter Toolbar */}
      <Card className="border-slate-800">
        <div className="flex flex-col sm:flex-row gap-3 justify-between items-start sm:items-center">
          <form onSubmit={handleSearchSubmit} className="flex items-center gap-2 w-full sm:w-80">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search title, CWE, package..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-slate-900 border border-slate-750 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <Button type="submit" variant="primary" size="sm">Search</Button>
          </form>

          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            {/* Severity Filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-slate-500 text-[11px]">Severity:</span>
              <select
                value={severity}
                onChange={(e) => {
                  setSeverity(e.target.value);
                  setPagination((prev) => ({ ...prev, page: 1 }));
                }}
                className="bg-slate-900 border border-slate-750 text-slate-300 text-xs rounded px-2 py-1 focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
                <option value="INFORMATIONAL">Informational</option>
              </select>
            </div>

            {/* Status Filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-slate-500 text-[11px]">Status:</span>
              <select
                value={status}
                onChange={(e) => {
                  setStatus(e.target.value);
                  setPagination((prev) => ({ ...prev, page: 1 }));
                }}
                className="bg-slate-900 border border-slate-750 text-slate-300 text-xs rounded px-2 py-1 focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Statuses</option>
                <option value="OPEN">Open</option>
                <option value="ACKNOWLEDGED">Acknowledged</option>
                <option value="IN_PROGRESS">In Progress</option>
                <option value="RESOLVED">Resolved</option>
                <option value="FALSE_POSITIVE">False Positive</option>
              </select>
            </div>

            {/* Sort */}
            <div className="flex items-center gap-1.5">
              <span className="text-slate-500 text-[11px]">Sort:</span>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="bg-slate-900 border border-slate-750 text-slate-300 text-xs rounded px-2 py-1 focus:outline-none focus:border-cyan-500"
              >
                <option value="created_at">Date</option>
                <option value="severity">Severity</option>
                <option value="status">Status</option>
                <option value="title">Title</option>
              </select>
              <button
                onClick={() => setSortOrder(sortOrder === 'ASC' ? 'DESC' : 'ASC')}
                className="px-2 py-1 bg-slate-900 border border-slate-750 rounded text-slate-400 hover:text-white"
              >
                {sortOrder}
              </button>
            </div>
          </div>
        </div>
      </Card>

      {loading && <LoadingSpinner message="Aggregating security findings across all application scans..." />}
      {error && <ErrorState title="Error Loading Findings" message={error} onRetry={fetchFindings} />}

      {/* Paginated Findings Table */}
      {!loading && !error && (
        <Card className="border-slate-800 p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 uppercase text-[10px]">
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Finding Title</th>
                  <th className="py-3 px-3">Category</th>
                  <th className="py-3 px-3">CWE</th>
                  <th className="py-3 px-3">Status</th>
                  <th className="py-3 px-4">Application</th>
                  <th className="py-3 px-3">Scan</th>
                  <th className="py-3 px-3">Detected</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {findings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-4 whitespace-nowrap">
                      <Badge
                        label={f.severity}
                        variant={
                          f.severity === 'CRITICAL'
                            ? 'danger'
                            : f.severity === 'HIGH'
                            ? 'warning'
                            : f.severity === 'MEDIUM'
                            ? 'amber'
                            : 'info'
                        }
                        size="xs"
                      />
                    </td>
                    <td className="py-3 px-4 font-semibold text-slate-200 truncate max-w-xs">
                      <Link
                        to={`/scans/${f.scanId}/findings/${f.id}`}
                        className="hover:text-cyan-400"
                        title={f.title}
                      >
                        {f.title}
                      </Link>
                    </td>
                    <td className="py-3 px-3 text-slate-400 whitespace-nowrap">{f.category}</td>
                    <td className="py-3 px-3 text-cyan-400 font-bold whitespace-nowrap">{f.cwe || '—'}</td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center gap-1 text-[11px] font-bold ${
                          f.status === 'RESOLVED'
                            ? 'text-emerald-400'
                            : f.status === 'FALSE_POSITIVE'
                            ? 'text-slate-500'
                            : 'text-red-400'
                        }`}
                      >
                        {f.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-300 truncate max-w-xs">
                      {f.application?.originalFilename}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <Link to={`/scans/${f.scanId}`} className="text-cyan-400 hover:underline">
                        #{f.scanId}
                      </Link>
                    </td>
                    <td className="py-3 px-3 text-slate-500 text-[11px] whitespace-nowrap">
                      {formatDate(f.createdAt)}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <Link to={`/scans/${f.scanId}/findings/${f.id}`}>
                        <Button variant="ghost" size="xs">
                          <ExternalLink className="h-3 w-3 mr-1" /> View Finding
                        </Button>
                      </Link>
                    </td>
                  </tr>
                ))}

                {findings.length === 0 && (
                  <tr>
                    <td colSpan={9} className="text-center py-8 text-slate-500 font-mono">
                      No security findings match the selected criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="p-3 border-t border-slate-800 bg-slate-900/30 flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">
              Page <span className="text-cyan-400 font-bold">{pagination.page}</span> of{' '}
              <span className="text-cyan-400 font-bold">{pagination.totalPages}</span> ({pagination.total} total)
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="xs"
                disabled={pagination.page <= 1}
                onClick={() => setPagination((prev) => ({ ...prev, page: prev.page - 1 }))}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="xs"
                disabled={pagination.page >= pagination.totalPages}
                onClick={() => setPagination((prev) => ({ ...prev, page: prev.page + 1 }))}
              >
                Next
              </Button>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
