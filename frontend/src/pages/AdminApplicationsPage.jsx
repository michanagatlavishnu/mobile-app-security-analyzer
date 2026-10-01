import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Layers,
  Search,
  ArrowUpDown,
  RefreshCw,
  ExternalLink,
  Shield,
  Activity,
  UploadCloud,
  Clock,
  AlertTriangle,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import adminService from '../services/adminService';
import { formatDate, getRiskScoreColor } from '../utils/formatters';

export default function AdminApplicationsPage() {
  const [apps, setApps] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 15, total: 0, totalPages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState('latest_uploaded');
  const [sortOrder, setSortOrder] = useState('DESC');

  const fetchApps = async () => {
    try {
      setLoading(true);
      setError('');
      const data = await adminService.getApplications({
        page: pagination.page,
        limit: pagination.limit,
        search,
        sortBy,
        sortOrder,
      });

      setApps(data.data || []);
      if (data.pagination) {
        setPagination(data.pagination);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to retrieve application catalog.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApps();
  }, [pagination.page, sortBy, sortOrder]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPagination((prev) => ({ ...prev, page: 1 }));
    fetchApps();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Application Inventory & Catalog"
        description="Grouped APK packages, multi-version tracking, historical scan scores, and lifecycle analysis."
        badge={<Badge label={`${pagination.total} Applications`} variant="info" />}
        actions={
          <Button variant="outline" size="sm" onClick={fetchApps} disabled={loading}>
            <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </Button>
        }
      />

      {/* Search and Sort Toolbar */}
      <Card className="border-slate-800">
        <div className="flex flex-col sm:flex-row gap-4 justify-between items-start sm:items-center">
          <form onSubmit={handleSearchSubmit} className="flex items-center gap-2 w-full sm:w-80">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search package or application..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-slate-900 border border-slate-750 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <Button type="submit" variant="primary" size="sm">Search</Button>
          </form>

          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-500 text-[11px] flex items-center gap-1">
              <ArrowUpDown className="h-3 w-3" /> Sort:
            </span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="bg-slate-900 border border-slate-750 text-slate-300 text-xs rounded px-2 py-1 focus:outline-none focus:border-cyan-500"
            >
              <option value="latest_uploaded">Latest Upload</option>
              <option value="last_analyzed">Last Analyzed</option>
              <option value="uploads">Upload Count</option>
              <option value="scans">Scan Count</option>
              <option value="latest_score">Security Score</option>
              <option value="package_name">Package Name</option>
            </select>
            <button
              onClick={() => setSortOrder(sortOrder === 'ASC' ? 'DESC' : 'ASC')}
              className="px-2 py-1 bg-slate-900 border border-slate-750 rounded text-slate-400 hover:text-white"
            >
              {sortOrder}
            </button>
          </div>
        </div>
      </Card>

      {loading && <LoadingSpinner message="Querying application inventory and version groups..." />}
      {error && <ErrorState title="Error Loading Applications" message={error} onRetry={fetchApps} />}

      {!loading && !error && (
        <Card className="border-slate-800 p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 uppercase text-[10px]">
                  <th className="py-3 px-4">Application</th>
                  <th className="py-3 px-4">Package Name</th>
                  <th className="py-3 px-3 text-center">Versions</th>
                  <th className="py-3 px-3 text-center">Uploads</th>
                  <th className="py-3 px-3 text-center">Scans</th>
                  <th className="py-3 px-3 text-center">Latest Score</th>
                  <th className="py-3 px-3">Latest Risk</th>
                  <th className="py-3 px-3">Last Analyzed</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {apps.map((app) => (
                  <tr key={app.identifier} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-4 font-semibold text-slate-200">
                      <Link
                        to={`/admin/applications/${encodeURIComponent(app.identifier)}`}
                        className="hover:text-cyan-400 flex items-center gap-1.5"
                      >
                        <Layers className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                        <span className="truncate max-w-xs">{app.displayName}</span>
                      </Link>
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px] truncate max-w-xs">
                      {app.packageName || '—'}
                    </td>
                    <td className="py-3 px-3 text-center">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-bold">
                        {app.versionsCount}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-center text-slate-300 font-bold">{app.uploadsCount}</td>
                    <td className="py-3 px-3 text-center text-slate-300 font-bold">{app.scansCount}</td>
                    <td className="py-3 px-3 text-center font-bold">
                      {app.latestSecurityScore !== null ? (
                        <span className={getRiskScoreColor(app.latestSecurityScore)}>
                          {app.latestSecurityScore}/100
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      {app.latestRiskLevel ? (
                        <Badge
                          label={app.latestRiskLevel}
                          variant={
                            app.latestRiskLevel === 'CRITICAL'
                              ? 'danger'
                              : app.latestRiskLevel === 'HIGH'
                              ? 'warning'
                              : 'info'
                          }
                          size="xs"
                        />
                      ) : (
                        <span className="text-slate-500 text-[11px]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                      {app.lastAnalyzedDate ? formatDate(app.lastAnalyzedDate) : 'Not analyzed'}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <Link to={`/admin/applications/${encodeURIComponent(app.identifier)}`}>
                        <Button variant="ghost" size="xs">
                          <ExternalLink className="h-3 w-3 mr-1" /> View History
                        </Button>
                      </Link>
                    </td>
                  </tr>
                ))}

                {apps.length === 0 && (
                  <tr>
                    <td colSpan={9} className="text-center py-8 text-slate-500 font-mono">
                      No applications found matching query.
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
