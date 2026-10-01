import React, { useState, useEffect } from 'react';
import { ShieldCheck, Users, Activity, AlertOctagon, RefreshCw, UserCheck, UserX, Shield, Database, HardDrive, FileText, CheckCircle2, Clock } from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import adminService from '../services/adminService';
import { formatDate } from '../utils/formatters';

export default function AdminPage() {
  const [metrics, setMetrics] = useState(null);
  const [users, setUsers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 25, total: 0, totalPages: 1 });
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const fetchAdminData = async () => {
    try {
      setLoading(true);
      setError('');
      const [metricsData, usersData, logsData] = await Promise.all([
        adminService.getMetrics(),
        adminService.getAllUsers(),
        adminService.getAuditLogs(pagination.page, pagination.limit)
      ]);
      setMetrics(metricsData.data);
      setUsers(usersData.data || []);
      setAuditLogs(logsData.data?.logs || []);
      if (logsData.data?.pagination) {
        setPagination(logsData.data.pagination);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load administrator data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAdminData();
  }, [pagination.page]);

  const handleRoleToggle = async (userId, currentRole) => {
    const newRole = currentRole === 'admin' ? 'user' : 'admin';
    try {
      setActionLoading(`role-${userId}`);
      await adminService.updateUserRole(userId, newRole);
      setMessage(`Successfully updated user role to ${newRole}`);
      setTimeout(() => setMessage(''), 3000);
      fetchAdminData();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update user role.');
    } finally {
      setActionLoading(null);
    }
  };

  const handleStatusToggle = async (userId, currentStatus) => {
    const newStatus = currentStatus === 'active' ? 'disabled' : 'active';
    try {
      setActionLoading(`status-${userId}`);
      await adminService.updateUserStatus(userId, newStatus);
      setMessage(`Successfully changed user status to ${newStatus}`);
      setTimeout(() => setMessage(''), 3000);
      fetchAdminData();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update user status.');
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Operations & Administration"
        description="Global system telemetry, user governance, access control, and immutable audit logs."
        badge={<Badge label="SecOps Admin Active" variant="danger" />}
        actions={
          <Button variant="outline" size="sm" onClick={fetchAdminData}>
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Refresh
          </Button>
        }
      />

      {message && (
        <div className="p-3.5 bg-emerald-950/40 border border-emerald-500/30 rounded-lg flex items-center gap-2 text-xs text-emerald-400 font-mono">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          <span>{message}</span>
        </div>
      )}

      {loading && <LoadingSpinner message="Fetching administrative metrics and telemetry from MySQL..." />}

      {error && <ErrorState title="Admin Access Notice" message={error} onRetry={fetchAdminData} />}

      {!loading && !error && (
        <>
          {/* Top KPI Telemetry Row */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card className="border-slate-800">
              <div className="flex items-center justify-between">
                <p className="text-xs font-mono text-slate-400 uppercase">Registered Users</p>
                <Users className="h-4 w-4 text-cyan-400" />
              </div>
              <p className="text-3xl font-extrabold text-white mt-2 font-mono">{metrics?.users?.total ?? 0}</p>
              <p className="text-[11px] text-slate-500 font-mono mt-1">Tenant isolated accounts</p>
            </Card>

            <Card className="border-slate-800">
              <div className="flex items-center justify-between">
                <p className="text-xs font-mono text-slate-400 uppercase">Total Scans Executed</p>
                <Activity className="h-4 w-4 text-sky-400" />
              </div>
              <p className="text-3xl font-extrabold text-white mt-2 font-mono">{metrics?.scans?.total ?? 0}</p>
              <div className="flex gap-2 text-[10px] font-mono mt-1 text-slate-400">
                <span className="text-emerald-400">{metrics?.scans?.completed ?? 0} Completed</span>
                <span>•</span>
                <span className="text-amber-400">{metrics?.scans?.active ?? 0} Active</span>
              </div>
            </Card>

            <Card className="border-slate-800">
              <div className="flex items-center justify-between">
                <p className="text-xs font-mono text-slate-400 uppercase">Security Findings</p>
                <AlertOctagon className="h-4 w-4 text-amber-400" />
              </div>
              <p className="text-3xl font-extrabold text-white mt-2 font-mono">{metrics?.vulnerabilities?.total ?? 0}</p>
              <div className="flex gap-2 text-[10px] font-mono mt-1">
                <span className="text-red-400">{metrics?.vulnerabilities?.critical ?? 0} Critical</span>
                <span>•</span>
                <span className="text-emerald-400">{metrics?.vulnerabilities?.resolved ?? 0} Resolved</span>
              </div>
            </Card>

            <Card className="border-slate-800">
              <div className="flex items-center justify-between">
                <p className="text-xs font-mono text-slate-400 uppercase">Secure APK Storage</p>
                <HardDrive className="h-4 w-4 text-emerald-400" />
              </div>
              <p className="text-3xl font-extrabold text-white mt-2 font-mono">{metrics?.apks?.totalMb ?? 0} <span className="text-sm font-normal text-slate-400">MB</span></p>
              <p className="text-[11px] text-slate-500 font-mono mt-1">{metrics?.apks?.total ?? 0} Encrypted Archive(s)</p>
            </Card>
          </div>

          {/* User Governance Table */}
          <Card title="User Access Governance" subtitle="Manage operator roles and account activation states">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                    <th className="py-2.5 px-3">User</th>
                    <th className="py-2.5 px-3">Email</th>
                    <th className="py-2.5 px-3">Role</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3 text-center">APKs</th>
                    <th className="py-2.5 px-3 text-center">Scans</th>
                    <th className="py-2.5 px-3">Registered</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {users.map((u) => (
                    <tr key={u.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-2.5 px-3 font-semibold text-slate-200">{u.name}</td>
                      <td className="py-2.5 px-3 text-slate-400">{u.email}</td>
                      <td className="py-2.5 px-3">
                        <Badge label={u.role.toUpperCase()} variant={u.role === 'admin' ? 'danger' : 'info'} size="sm" />
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`inline-flex items-center gap-1 text-[11px] ${u.status === 'active' ? 'text-emerald-400' : 'text-red-400'}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${u.status === 'active' ? 'bg-emerald-400' : 'bg-red-400'}`} />
                          {u.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-center text-slate-300">{u.total_apks}</td>
                      <td className="py-2.5 px-3 text-center text-slate-300">{u.total_scans}</td>
                      <td className="py-2.5 px-3 text-slate-500 text-[11px]">{formatDate(u.created_at)}</td>
                      <td className="py-2.5 px-3 text-right space-x-2">
                        <Button
                          variant="ghost"
                          size="xs"
                          loading={actionLoading === `role-${u.id}`}
                          onClick={() => handleRoleToggle(u.id, u.role)}
                          title="Toggle Admin / User Role"
                        >
                          <Shield className="h-3 w-3 mr-1" />
                          {u.role === 'admin' ? 'Demote' : 'Promote'}
                        </Button>
                        <Button
                          variant="ghost"
                          size="xs"
                          loading={actionLoading === `status-${u.id}`}
                          onClick={() => handleStatusToggle(u.id, u.status)}
                          className={u.status === 'active' ? 'text-red-400 hover:text-red-300' : 'text-emerald-400 hover:text-emerald-300'}
                          title="Toggle Account Activation"
                        >
                          {u.status === 'active' ? <UserX className="h-3 w-3 mr-1" /> : <UserCheck className="h-3 w-3 mr-1" />}
                          {u.status === 'active' ? 'Disable' : 'Enable'}
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          {/* System Audit Logs */}
          <Card
            title="System Security Audit Trail"
            subtitle="Immutable operational event log across all users and analysis actions"
          >
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Operator</th>
                    <th className="py-2.5 px-3">Action</th>
                    <th className="py-2.5 px-3">Entity</th>
                    <th className="py-2.5 px-3">Details</th>
                    <th className="py-2.5 px-3">IP Address</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {auditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-2.5 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                        {formatDate(log.created_at)}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {log.user_name ? (
                          <span>{log.user_name} <span className="text-[10px] text-slate-500">({log.user_role})</span></span>
                        ) : (
                          <span className="text-slate-500">System</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3">
                        <Badge label={log.action} variant="cyan" size="sm" />
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">
                        {log.entity_type ? `${log.entity_type} #${log.entity_id || ''}` : '—'}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate" title={log.details}>
                        {log.details || '—'}
                      </td>
                      <td className="py-2.5 px-3 text-slate-500 text-[11px] whitespace-nowrap">
                        {log.ip_address || '127.0.0.1'}
                      </td>
                    </tr>
                  ))}
                  {auditLogs.length === 0 && (
                    <tr>
                      <td colSpan={6} className="text-center py-6 text-slate-500">
                        No audit events recorded yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
