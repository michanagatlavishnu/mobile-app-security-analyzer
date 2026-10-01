import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  FileText,
  Search,
  Filter,
  RefreshCw,
  Calendar,
  Shield,
  User,
  Activity,
  Layers,
  CheckCircle2,
  Lock,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import adminService from '../services/adminService';
import { formatDate } from '../utils/formatters';

export default function AdminAuditLogsPage() {
  const [logs, setLogs] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 30, total: 0, totalPages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Filters
  const [userSearch, setUserSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('all');
  const [entityFilter, setEntityFilter] = useState('all');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  const fetchLogs = async () => {
    try {
      setLoading(true);
      setError('');
      const data = await adminService.getAuditLogs({
        page: pagination.page,
        limit: pagination.limit,
        user: userSearch,
        action: actionFilter !== 'all' ? actionFilter : '',
        entityType: entityFilter !== 'all' ? entityFilter : '',
        startDate,
        endDate,
      });

      setLogs(data.data?.logs || []);
      if (data.data?.pagination) {
        setPagination(data.data.pagination);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to retrieve immutable security audit trail.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [pagination.page, actionFilter, entityFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPagination((prev) => ({ ...prev, page: 1 }));
    fetchLogs();
  };

  const handleClearFilters = () => {
    setUserSearch('');
    setActionFilter('all');
    setEntityFilter('all');
    setStartDate('');
    setEndDate('');
    setPagination((prev) => ({ ...prev, page: 1 }));
  };

  const getActionBadgeVariant = (action) => {
    if (action.includes('DISABLED') || action.includes('FAILED') || action.includes('DELETE')) return 'danger';
    if (action.includes('ENABLED') || action.includes('COMPLETED') || action.includes('REGISTER')) return 'success';
    if (action.includes('ROLE') || action.includes('UPDATED')) return 'warning';
    return 'cyan';
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Operations Audit Trail"
        description="Immutable administrative mutations, authentication events, scan lifecycle transitions, and system actions."
        badge={<Badge label={`${pagination.total} Log Entries`} variant="info" />}
        actions={
          <Button variant="outline" size="sm" onClick={fetchLogs} disabled={loading}>
            <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </Button>
        }
      />

      {/* Filter and Query Toolbar */}
      <Card className="border-slate-800">
        <form onSubmit={handleSearchSubmit} className="space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            {/* User Search */}
            <div className="relative">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="text"
                placeholder="User name, email, or ID..."
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
                className="w-full bg-slate-900 border border-slate-750 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Action Filter */}
            <div>
              <select
                value={actionFilter}
                onChange={(e) => {
                  setActionFilter(e.target.value);
                  setPagination((prev) => ({ ...prev, page: 1 }));
                }}
                className="w-full bg-slate-900 border border-slate-750 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="all">All Actions</option>
                <option value="USER_LOGIN">USER_LOGIN</option>
                <option value="USER_REGISTERED">USER_REGISTERED</option>
                <option value="ROLE_CHANGED">ROLE_CHANGED</option>
                <option value="USER_DISABLED">USER_DISABLED</option>
                <option value="USER_ENABLED">USER_ENABLED</option>
                <option value="APK_UPLOADED">APK_UPLOADED</option>
                <option value="APK_DELETED">APK_DELETED</option>
                <option value="SCAN_STARTED">SCAN_STARTED</option>
                <option value="SCAN_COMPLETED">SCAN_COMPLETED</option>
                <option value="SCAN_FAILED">SCAN_FAILED</option>
                <option value="REPORT_GENERATED">REPORT_GENERATED</option>
                <option value="FINDING_STATUS_UPDATED">FINDING_STATUS_UPDATED</option>
              </select>
            </div>

            {/* Resource/Entity Filter */}
            <div>
              <select
                value={entityFilter}
                onChange={(e) => {
                  setEntityFilter(e.target.value);
                  setPagination((prev) => ({ ...prev, page: 1 }));
                }}
                className="w-full bg-slate-900 border border-slate-750 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="all">All Entity Types</option>
                <option value="user">User</option>
                <option value="apk">APK File</option>
                <option value="scan">Scan</option>
                <option value="vulnerability">Vulnerability</option>
                <option value="report">Report</option>
              </select>
            </div>

            {/* Date Range Start */}
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] font-mono text-slate-500">From:</span>
              <input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="w-full bg-slate-900 border border-slate-750 text-slate-300 text-xs rounded-lg px-2 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Date Range End */}
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] font-mono text-slate-500">To:</span>
              <input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="w-full bg-slate-900 border border-slate-750 text-slate-300 text-xs rounded-lg px-2 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 pt-1">
            <Button type="button" variant="outline" size="xs" onClick={handleClearFilters}>
              Reset Filters
            </Button>
            <Button type="submit" variant="primary" size="xs">
              Apply Filters
            </Button>
          </div>
        </form>
      </Card>

      {loading && <LoadingSpinner message="Querying immutable audit event records..." />}
      {error && <ErrorState title="Error Loading Audit Trail" message={error} onRetry={fetchLogs} />}

      {!loading && !error && (
        <Card className="border-slate-800 p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 uppercase text-[10px]">
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Operator</th>
                  <th className="py-3 px-3">Action Event</th>
                  <th className="py-3 px-3">Resource / Entity</th>
                  <th className="py-3 px-4">Audit Details</th>
                  <th className="py-3 px-4 text-right">IP Address</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                      {formatDate(log.created_at)}
                    </td>
                    <td className="py-3 px-4">
                      {log.user_name ? (
                        <Link to={`/admin/users/${log.user_id}`} className="hover:text-cyan-400">
                          <p className="font-semibold text-slate-200">{log.user_name}</p>
                          <p className="text-[10px] text-slate-500">{log.user_email || `ID #${log.user_id}`}</p>
                        </Link>
                      ) : (
                        <span className="text-slate-500 font-semibold">System / Cron</span>
                      )}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <Badge
                        label={log.action}
                        variant={getActionBadgeVariant(log.action)}
                        size="xs"
                      />
                    </td>
                    <td className="py-3 px-3 text-slate-400 whitespace-nowrap">
                      {log.entity_type ? `${log.entity_type} #${log.entity_id || ''}` : '—'}
                    </td>
                    <td className="py-3 px-4 text-slate-300 max-w-md truncate" title={log.details}>
                      {log.details || '—'}
                    </td>
                    <td className="py-3 px-4 text-right text-slate-500 text-[11px] whitespace-nowrap">
                      {log.ip_address || '127.0.0.1'}
                    </td>
                  </tr>
                ))}

                {logs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="text-center py-8 text-slate-500 font-mono">
                      No audit events match the specified filter parameters.
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
              <span className="text-cyan-400 font-bold">{pagination.totalPages}</span> ({pagination.total} total logs)
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
