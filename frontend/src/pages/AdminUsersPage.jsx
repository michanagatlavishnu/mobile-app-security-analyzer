import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Users,
  Search,
  Filter,
  ArrowUpDown,
  Shield,
  ShieldCheck,
  UserX,
  UserCheck,
  Eye,
  AlertTriangle,
  RefreshCw,
  CheckCircle2,
  X,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import Modal from '../components/Modal';
import adminService from '../services/adminService';
import { formatDate } from '../utils/formatters';

export default function AdminUsersPage() {
  const [users, setUsers] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 15, total: 0, totalPages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  // Filters & Sorting state
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all'); // 'all' | 'active' | 'disabled' | 'admin' | 'analyst'
  const [sortBy, setSortBy] = useState('created_at');
  const [sortOrder, setSortOrder] = useState('DESC');

  // Confirmation Modal state
  const [modalState, setModalState] = useState({
    open: false,
    type: null, // 'status' | 'role'
    user: null,
    targetValue: null,
    loading: false,
    error: '',
  });

  const fetchUsers = async () => {
    try {
      setLoading(true);
      setError('');
      const data = await adminService.getUsers({
        page: pagination.page,
        limit: pagination.limit,
        search,
        filter,
        sortBy,
        sortOrder,
      });

      setUsers(data.data || []);
      if (data.pagination) {
        setPagination(data.pagination);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to retrieve user registry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, [pagination.page, filter, sortBy, sortOrder]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPagination((prev) => ({ ...prev, page: 1 }));
    fetchUsers();
  };

  // Open Confirmation Modal
  const openStatusModal = (user) => {
    const nextStatus = user.status === 'active' ? 'disabled' : 'active';
    setModalState({
      open: true,
      type: 'status',
      user,
      targetValue: nextStatus,
      loading: false,
      error: '',
    });
  };

  const openRoleModal = (user) => {
    const nextRole = user.role === 'admin' ? 'user' : 'admin';
    setModalState({
      open: true,
      type: 'role',
      user,
      targetValue: nextRole,
      loading: false,
      error: '',
    });
  };

  // Confirm Modal Action
  const executeModalAction = async () => {
    const { type, user, targetValue } = modalState;
    if (!user || !type) return;

    try {
      setModalState((prev) => ({ ...prev, loading: true, error: '' }));

      if (type === 'status') {
        await adminService.updateUserStatus(user.id, targetValue);
        setNotice(`Account for ${user.email} successfully ${targetValue === 'active' ? 'enabled' : 'disabled'}.`);
      } else if (type === 'role') {
        await adminService.updateUserRole(user.id, targetValue);
        setNotice(`Role for ${user.email} updated to ${targetValue === 'admin' ? 'Administrator' : 'Analyst'}.`);
      }

      setModalState({ open: false, type: null, user: null, targetValue: null, loading: false, error: '' });
      setTimeout(() => setNotice(''), 4000);
      fetchUsers();
    } catch (err) {
      setModalState((prev) => ({
        ...prev,
        loading: false,
        error: err.response?.data?.error || err.response?.data?.message || 'Action rejected by server policy.',
      }));
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="User Access Governance"
        description="Search, filter, inspect, and manage operator accounts, roles, and status."
        badge={<Badge label={`${pagination.total} Accounts`} variant="info" />}
        actions={
          <Button variant="outline" size="sm" onClick={fetchUsers} disabled={loading}>
            <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </Button>
        }
      />

      {notice && (
        <div className="p-3.5 bg-emerald-950/40 border border-emerald-500/30 rounded-lg flex items-center justify-between text-xs text-emerald-400 font-mono">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{notice}</span>
          </div>
          <button onClick={() => setNotice('')} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Search, Filter & Sort Controls */}
      <Card className="border-slate-800">
        <div className="flex flex-col lg:flex-row gap-4 justify-between items-start lg:items-center">
          {/* Search Form */}
          <form onSubmit={handleSearchSubmit} className="flex items-center gap-2 w-full lg:w-80">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search name or email..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-slate-900 border border-slate-750 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <Button type="submit" variant="primary" size="sm">Search</Button>
          </form>

          {/* Filter Pills */}
          <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
            <span className="text-slate-500 text-[11px] mr-1 flex items-center gap-1">
              <Filter className="h-3 w-3" /> Status:
            </span>
            {['all', 'active', 'disabled', 'admin', 'analyst'].map((f) => (
              <button
                key={f}
                onClick={() => {
                  setFilter(f);
                  setPagination((prev) => ({ ...prev, page: 1 }));
                }}
                className={`px-2.5 py-1 rounded text-[11px] uppercase transition-colors ${
                  filter === f
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 bg-slate-900/50'
                }`}
              >
                {f}
              </button>
            ))}
          </div>

          {/* Sort Dropdown */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-500 text-[11px] flex items-center gap-1">
              <ArrowUpDown className="h-3 w-3" /> Sort:
            </span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="bg-slate-900 border border-slate-750 text-slate-300 text-xs rounded px-2 py-1 focus:outline-none focus:border-cyan-500"
            >
              <option value="created_at">Registration Date</option>
              <option value="last_login">Last Login</option>
              <option value="total_scans">Scan Count</option>
              <option value="total_apks">Upload Count</option>
              <option value="status">Status</option>
              <option value="name">Name</option>
            </select>
            <button
              onClick={() => setSortOrder(sortOrder === 'ASC' ? 'DESC' : 'ASC')}
              className="px-2 py-1 bg-slate-900 border border-slate-750 rounded text-slate-400 hover:text-white"
              title="Toggle sort direction"
            >
              {sortOrder}
            </button>
          </div>
        </div>
      </Card>

      {/* Users Data Table */}
      {loading && <LoadingSpinner message="Fetching user accounts from registry..." />}
      {error && <ErrorState title="Error Loading Users" message={error} onRetry={fetchUsers} />}

      {!loading && !error && (
        <Card className="border-slate-800 p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/50 text-slate-400 uppercase text-[10px]">
                  <th className="py-3 px-4">User</th>
                  <th className="py-3 px-4">Email</th>
                  <th className="py-3 px-3">Role</th>
                  <th className="py-3 px-3">Status</th>
                  <th className="py-3 px-3">Registration</th>
                  <th className="py-3 px-3">Last Login</th>
                  <th className="py-3 px-3 text-center">APKs</th>
                  <th className="py-3 px-3 text-center">Scans</th>
                  <th className="py-3 px-3">Last Activity</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-4 font-semibold text-slate-200">
                      <Link to={`/admin/users/${u.id}`} className="hover:text-cyan-400 flex items-center gap-1.5">
                        {u.name}
                      </Link>
                    </td>
                    <td className="py-3 px-4 text-slate-400">{u.email}</td>
                    <td className="py-3 px-3">
                      <Badge
                        label={u.role === 'admin' ? 'ADMIN' : 'ANALYST'}
                        variant={u.role === 'admin' ? 'danger' : 'info'}
                        size="xs"
                      />
                    </td>
                    <td className="py-3 px-3">
                      <span className={`inline-flex items-center gap-1.5 text-[11px] ${u.status === 'active' ? 'text-emerald-400' : 'text-red-400'}`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${u.status === 'active' ? 'bg-emerald-400' : 'bg-red-400'}`} />
                        {u.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-500 text-[11px] whitespace-nowrap">{formatDate(u.created_at)}</td>
                    <td className="py-3 px-3 text-slate-400 text-[11px] whitespace-nowrap">{u.last_login ? formatDate(u.last_login) : 'Never'}</td>
                    <td className="py-3 px-3 text-center text-slate-300 font-bold">{u.total_apks}</td>
                    <td className="py-3 px-3 text-center text-slate-300 font-bold">{u.total_scans}</td>
                    <td className="py-3 px-3 text-slate-400 text-[11px] whitespace-nowrap">{u.last_activity ? formatDate(u.last_activity) : '—'}</td>
                    <td className="py-3 px-4 text-right space-x-1 whitespace-nowrap">
                      {/* View Details */}
                      <Link to={`/admin/users/${u.id}`}>
                        <Button variant="ghost" size="xs" title="View Detailed Profile">
                          <Eye className="h-3 w-3 mr-1" /> View
                        </Button>
                      </Link>

                      {/* Role Toggle */}
                      <Button
                        variant="ghost"
                        size="xs"
                        onClick={() => openRoleModal(u)}
                        title="Change Account Role"
                      >
                        <Shield className="h-3 w-3 mr-1" />
                        {u.role === 'admin' ? 'Demote' : 'Promote'}
                      </Button>

                      {/* Status Toggle */}
                      <Button
                        variant="ghost"
                        size="xs"
                        onClick={() => openStatusModal(u)}
                        className={u.status === 'active' ? 'text-red-400 hover:text-red-300' : 'text-emerald-400 hover:text-emerald-300'}
                        title="Toggle Activation Status"
                      >
                        {u.status === 'active' ? <UserX className="h-3 w-3 mr-1" /> : <UserCheck className="h-3 w-3 mr-1" />}
                        {u.status === 'active' ? 'Disable' : 'Enable'}
                      </Button>
                    </td>
                  </tr>
                ))}

                {users.length === 0 && (
                  <tr>
                    <td colSpan={10} className="text-center py-8 text-slate-500 font-mono">
                      No user accounts match the current filter or search criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          <div className="p-3 border-t border-slate-800 bg-slate-900/30 flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">
              Showing page <span className="text-cyan-400 font-bold">{pagination.page}</span> of{' '}
              <span className="text-cyan-400 font-bold">{pagination.totalPages}</span> ({pagination.total} users)
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

      {/* Confirmation Modal for Sensitive Actions (Phase 6) */}
      <Modal
        isOpen={modalState.open}
        onClose={() => setModalState({ open: false, type: null, user: null, targetValue: null, loading: false, error: '' })}
        title={modalState.type === 'status' ? 'Confirm Account Status Change' : 'Confirm Role Modification'}
      >
        <div className="space-y-4">
          <div className="p-3 bg-amber-950/30 border border-amber-500/30 rounded-lg flex items-start gap-3 text-xs text-amber-300 font-mono">
            <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-bold">Privileged Administrative Operation</p>
              {modalState.type === 'status' ? (
                <p className="mt-1 text-slate-300">
                  {modalState.targetValue === 'disabled'
                    ? `Are you sure you want to disable ${modalState.user?.email}? The user will immediately be barred from signing in and their active tokens will be revoked.`
                    : `Re-enable account for ${modalState.user?.email}? The user will regain access to their dashboard and scans.`}
                </p>
              ) : (
                <p className="mt-1 text-slate-300">
                  Changing role for <span className="text-white font-bold">{modalState.user?.email}</span> to{' '}
                  <span className="text-cyan-400 font-bold">{modalState.targetValue?.toUpperCase()}</span> will immediately alter their system authorizations and permissions. Continue?
                </p>
              )}
            </div>
          </div>

          {modalState.error && (
            <div className="p-3 bg-red-950/40 border border-red-500/40 rounded-lg text-xs font-mono text-red-400">
              {modalState.error}
            </div>
          )}

          <div className="flex items-center justify-end gap-2 pt-2">
            <Button
              variant="outline"
              size="sm"
              disabled={modalState.loading}
              onClick={() => setModalState({ open: false, type: null, user: null, targetValue: null, loading: false, error: '' })}
            >
              Cancel
            </Button>
            <Button
              variant={modalState.targetValue === 'disabled' ? 'danger' : 'primary'}
              size="sm"
              loading={modalState.loading}
              onClick={executeModalAction}
            >
              Confirm & Execute
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
