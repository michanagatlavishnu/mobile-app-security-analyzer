import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  Search,
  Filter,
  ArrowUpDown,
  RefreshCw,
  ExternalLink,
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Calendar,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import adminService from '../services/adminService';
import { formatDate, getRiskScoreColor } from '../utils/formatters';

export default function AdminScansPage() {
  const [scans, setScans] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 15, total: 0, totalPages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Filters & Sorting
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const [riskLevel, setRiskLevel] = useState('all');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState('DESC');

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError('');
      const data = await adminService.getScans({
        page: pagination.page,
        limit: pagination.limit,
        status: status !== 'all' ? status : '',
        riskLevel: riskLevel !== 'all' ? riskLevel : '',
        search,
        sortBy,
        sortOrder,
      });

      setScans(data.data || []);
      if (data.pagination) {
        setPagination(data.pagination);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to retrieve platform scans.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [pagination.page, status, riskLevel, sortBy, sortOrder]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPagination((prev) => ({ ...prev, page: 1 }));
    fetchScans();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform Scan Management"
        description="Global inspection of all static security analysis executions, risk levels, and findings."
        badge={<Badge label={`${pagination.total} Scans`} variant="cyan" />}
        actions={
          <Button variant="outline" size="sm" onClick={fetchScans} disabled={loading}>
            <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </Button>
        }
      />

      {/* Filter and Search Bar */}
      <Card className="border-slate-800">
        <div className="flex flex-col lg:flex-row gap-3 justify-between items-start lg:items-center">
          <form onSubmit={handleSearchSubmit} className="flex items-center gap-2 w-full lg:w-80">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search APK, package, user..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-slate-900 border border-slate-750 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <Button type="submit" variant="primary" size="sm">Search</Button>
          </form>

          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
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
                <option value="completed">Completed</option>
                <option value="failed">Failed</option>
                <option value="analyzing">Analyzing</option>
                <option value="extracting">Extracting</option>
                <option value="uploaded">Uploaded</option>
              </select>
            </div>

            {/* Risk Level Filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-slate-500 text-[11px]">Risk:</span>
              <select
                value={riskLevel}
                onChange={(e) => {
                  setRiskLevel(e.target.value);
                  setPagination((prev) => ({ ...prev, page: 1 }));
                }}
                className="bg-slate-900 border border-slate-750 text-slate-300 text-xs rounded px-2 py-1 focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Risks</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            {/* Sort Filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-slate-500 text-[11px]">Sort:</span>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="bg-slate-900 border border-slate-750 text-slate-300 text-xs rounded px-2 py-1 focus:outline-none focus:border-cyan-500"
              >
                <option value="created_at">Date</option>
                <option value="security_score">Score</option>
                <option value="status">Status</option>
                <option value="id">Scan ID</option>
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

      {loading && <LoadingSpinner message="Loading scan evaluation records across the platform..." />}
      {error && <ErrorState title="Error Loading Scans" message={error} onRetry={fetchScans} />}

      {!loading && !error && (
        <Card className="border-slate-800 p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 uppercase text-[10px]">
                  <th className="py-3 px-4">Scan ID</th>
                  <th className="py-3 px-3">Operator</th>
                  <th className="py-3 px-4">Application</th>
                  <th className="py-3 px-4">Package</th>
                  <th className="py-3 px-3">Execution Date</th>
                  <th className="py-3 px-3">Status</th>
                  <th className="py-3 px-3 text-center">Score</th>
                  <th className="py-3 px-3">Risk</th>
                  <th className="py-3 px-3 text-center">Findings</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {scans.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-4 text-cyan-400 font-bold">#{s.id}</td>
                    <td className="py-3 px-3">
                      <Link to={`/admin/users/${s.userId}`} className="hover:text-cyan-400">
                        <p className="font-semibold text-slate-200">{s.userName}</p>
                        <p className="text-[10px] text-slate-500 truncate">{s.userEmail}</p>
                      </Link>
                    </td>
                    <td className="py-3 px-4 font-semibold text-slate-200 truncate max-w-xs">{s.originalFilename}</td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px] truncate max-w-xs">{s.packageName || '—'}</td>
                    <td className="py-3 px-3 text-slate-400 text-[11px] whitespace-nowrap">{formatDate(s.createdAt)}</td>
                    <td className="py-3 px-3">
                      <Badge
                        label={s.status.toUpperCase()}
                        variant={s.status === 'completed' ? 'success' : s.status === 'failed' ? 'danger' : 'warning'}
                        size="xs"
                      />
                    </td>
                    <td className="py-3 px-3 text-center font-bold text-slate-200">
                      {s.securityScore !== null ? `${s.securityScore}/100` : '—'}
                    </td>
                    <td className="py-3 px-3">
                      {s.riskLevel ? (
                        <span className={`text-[11px] font-bold ${getRiskScoreColor(s.securityScore || 0)}`}>
                          {s.riskLevel}
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[11px]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-center text-slate-300 font-bold">
                      {s.vulnerabilities?.total ?? 0}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <Link to={`/scans/${s.id}`}>
                        <Button variant="ghost" size="xs">
                          <ExternalLink className="h-3 w-3 mr-1" /> View Scan
                        </Button>
                      </Link>
                    </td>
                  </tr>
                ))}

                {scans.length === 0 && (
                  <tr>
                    <td colSpan={10} className="text-center py-8 text-slate-500 font-mono">
                      No scan executions found matching selected criteria.
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
