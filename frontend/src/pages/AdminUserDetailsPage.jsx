import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  User,
  Shield,
  ShieldCheck,
  UserX,
  UserCheck,
  Activity,
  UploadCloud,
  CheckCircle2,
  XCircle,
  AlertOctagon,
  Clock,
  ArrowLeft,
  RefreshCw,
  AlertTriangle,
  FileText,
  Calendar,
  ExternalLink,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import Modal from '../components/Modal';
import adminService from '../services/adminService';
import { formatDate, getRiskScoreColor, getSeverityColor } from '../utils/formatters';

export default function AdminUserDetailsPage() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [userData, setUserData] = useState(null);

  // Modal State
  const [modalState, setModalState] = useState({
    open: false,
    type: null, // 'status' | 'role'
    targetValue: null,
    loading: false,
    error: '',
  });

  const fetchUserDetails = async () => {
    try {
      setLoading(true);
      setError('');
      const res = await adminService.getUserDetails(id);
      setUserData(res.data);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to retrieve operator details.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUserDetails();
  }, [id]);

  const handleAction = async () => {
    const { type, targetValue } = modalState;
    if (!type) return;

    try {
      setModalState((prev) => ({ ...prev, loading: true, error: '' }));
      if (type === 'status') {
        await adminService.updateUserStatus(id, targetValue);
        setNotice(`Account status updated to ${targetValue}.`);
      } else if (type === 'role') {
        await adminService.updateUserRole(id, targetValue);
        setNotice(`Account role updated to ${targetValue === 'admin' ? 'Administrator' : 'Analyst'}.`);
      }
      setModalState({ open: false, type: null, targetValue: null, loading: false, error: '' });
      setTimeout(() => setNotice(''), 4000);
      fetchUserDetails();
    } catch (err) {
      setModalState((prev) => ({
        ...prev,
        loading: false,
        error: err.response?.data?.error || err.response?.data?.message || 'Operation rejected.',
      }));
    }
  };

  const account = userData?.account || {};
  const usage = userData?.usage || {};
  const recentScans = userData?.recentScans || [];
  const recentActivity = userData?.recentActivity || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link to="/admin/users">
          <Button variant="outline" size="sm">
            <ArrowLeft className="h-3.5 w-3.5 mr-1.5" /> Back to Users
          </Button>
        </Link>
      </div>

      {notice && (
        <div className="p-3.5 bg-emerald-950/40 border border-emerald-500/30 rounded-lg flex items-center justify-between text-xs text-emerald-400 font-mono">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{notice}</span>
          </div>
          <button onClick={() => setNotice('')} className="text-slate-400 hover:text-white">✕</button>
        </div>
      )}

      {loading && <LoadingSpinner message="Loading account details and activity history..." />}
      {error && <ErrorState title="Account Retrieval Notice" message={error} onRetry={fetchUserDetails} />}

      {!loading && !error && userData && (
        <>
          <PageHeader
            title={account.name}
            description={`Account ID #${account.id} • ${account.email}`}
            badge={
              <div className="flex items-center gap-2">
                <Badge
                  label={account.role === 'admin' ? 'ADMINISTRATOR' : 'SECURITY ANALYST'}
                  variant={account.role === 'admin' ? 'danger' : 'info'}
                />
                <Badge
                  label={account.status.toUpperCase()}
                  variant={account.status === 'active' ? 'success' : 'danger'}
                />
              </div>
            }
            actions={
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    setModalState({
                      open: true,
                      type: 'role',
                      targetValue: account.role === 'admin' ? 'user' : 'admin',
                      loading: false,
                      error: '',
                    })
                  }
                >
                  <Shield className="h-3.5 w-3.5 mr-1.5" />
                  {account.role === 'admin' ? 'Demote to Analyst' : 'Promote to Admin'}
                </Button>
                <Button
                  variant={account.status === 'active' ? 'danger' : 'primary'}
                  size="sm"
                  onClick={() =>
                    setModalState({
                      open: true,
                      type: 'status',
                      targetValue: account.status === 'active' ? 'disabled' : 'active',
                      loading: false,
                      error: '',
                    })
                  }
                >
                  {account.status === 'active' ? (
                    <>
                      <UserX className="h-3.5 w-3.5 mr-1.5" /> Disable User
                    </>
                  ) : (
                    <>
                      <UserCheck className="h-3.5 w-3.5 mr-1.5" /> Enable User
                    </>
                  )}
                </Button>
              </div>
            }
          />

          {/* Account Meta & Usage Metrics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Account Info */}
            <Card title="Account Metadata" subtitle="Core identity attributes">
              <div className="space-y-2.5 text-xs font-mono mt-1">
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500">Name:</span>
                  <span className="text-slate-200 font-semibold">{account.name}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500">Email:</span>
                  <span className="text-slate-300">{account.email}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500">Role:</span>
                  <span className="text-cyan-400 font-bold">{account.role?.toUpperCase()}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500">Status:</span>
                  <span className={account.status === 'active' ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>
                    {account.status?.toUpperCase()}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500">Registered:</span>
                  <span className="text-slate-400">{formatDate(account.created_at)}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500">Last Login:</span>
                  <span className="text-slate-300">{account.last_login ? formatDate(account.last_login) : 'Never'}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-500">Last Activity:</span>
                  <span className="text-slate-300">{account.last_activity ? formatDate(account.last_activity) : '—'}</span>
                </div>
              </div>
            </Card>

            {/* Usage Stats */}
            <Card title="Platform Utilization" subtitle="Ingestion and execution volumes">
              <div className="grid grid-cols-2 gap-3 mt-1 font-mono text-center">
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
                  <p className="text-[10px] uppercase text-slate-500">Uploaded APKs</p>
                  <p className="text-xl font-bold text-emerald-400 mt-1">{usage.apkUploads ?? 0}</p>
                </div>
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
                  <p className="text-[10px] uppercase text-slate-500">Total Scans</p>
                  <p className="text-xl font-bold text-cyan-400 mt-1">{usage.totalScans ?? 0}</p>
                </div>
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
                  <p className="text-[10px] uppercase text-slate-500">Completed Scans</p>
                  <p className="text-xl font-bold text-sky-400 mt-1">{usage.completedScans ?? 0}</p>
                </div>
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
                  <p className="text-[10px] uppercase text-slate-500">Failed Scans</p>
                  <p className="text-xl font-bold text-red-400 mt-1">{usage.failedScans ?? 0}</p>
                </div>
                <div className="col-span-2 p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
                  <p className="text-[10px] uppercase text-slate-500">Average Security Score</p>
                  <p className="text-2xl font-black text-white mt-1">
                    {usage.avgSecurityScore !== null ? `${usage.avgSecurityScore}/100` : '—'}
                  </p>
                </div>
              </div>
            </Card>

            {/* Vulnerability Footprint */}
            <Card title="Detected Findings" subtitle="Vulnerability totals across user scans">
              <div className="grid grid-cols-2 gap-3 mt-1 font-mono text-center">
                <div className="p-3 bg-red-950/20 border border-red-500/30 rounded-lg">
                  <p className="text-[10px] uppercase text-red-400">Critical</p>
                  <p className="text-xl font-bold text-red-400 mt-1">{usage.criticalFindings ?? 0}</p>
                </div>
                <div className="p-3 bg-orange-950/20 border border-orange-500/30 rounded-lg">
                  <p className="text-[10px] uppercase text-orange-400">High</p>
                  <p className="text-xl font-bold text-orange-400 mt-1">{usage.highFindings ?? 0}</p>
                </div>
                <div className="p-3 bg-amber-950/20 border border-amber-500/30 rounded-lg">
                  <p className="text-[10px] uppercase text-amber-400">Medium</p>
                  <p className="text-xl font-bold text-amber-400 mt-1">{usage.mediumFindings ?? 0}</p>
                </div>
                <div className="p-3 bg-blue-950/20 border border-blue-500/30 rounded-lg">
                  <p className="text-[10px] uppercase text-blue-400">Low</p>
                  <p className="text-xl font-bold text-blue-400 mt-1">{usage.lowFindings ?? 0}</p>
                </div>
              </div>
            </Card>
          </div>

          {/* Recent Scans Table */}
          <Card title="Recent APK Scans" subtitle="Latest static security analyses performed by this operator">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                    <th className="py-2.5 px-3">Scan ID</th>
                    <th className="py-2.5 px-3">APK File</th>
                    <th className="py-2.5 px-3">Package</th>
                    <th className="py-2.5 px-3">Date</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3 text-center">Score</th>
                    <th className="py-2.5 px-3">Risk</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {recentScans.map((s) => (
                    <tr key={s.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">#{s.id}</td>
                      <td className="py-2.5 px-3 font-semibold text-slate-200">{s.original_filename}</td>
                      <td className="py-2.5 px-3 text-slate-400">{s.package_name || '—'}</td>
                      <td className="py-2.5 px-3 text-slate-500 text-[11px] whitespace-nowrap">{formatDate(s.created_at)}</td>
                      <td className="py-2.5 px-3">
                        <Badge
                          label={s.status.toUpperCase()}
                          variant={s.status === 'completed' ? 'success' : s.status === 'failed' ? 'danger' : 'warning'}
                          size="xs"
                        />
                      </td>
                      <td className="py-2.5 px-3 text-center font-bold text-slate-200">
                        {s.security_score !== null ? `${s.security_score}/100` : '—'}
                      </td>
                      <td className="py-2.5 px-3">
                        {s.risk_level ? (
                          <span className={`text-[11px] font-bold ${getRiskScoreColor(s.security_score || 0)}`}>
                            {s.risk_level}
                          </span>
                        ) : '—'}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <Link to={`/scans/${s.id}`}>
                          <Button variant="ghost" size="xs">
                            <ExternalLink className="h-3 w-3 mr-1" /> View Scan
                          </Button>
                        </Link>
                      </td>
                    </tr>
                  ))}
                  {recentScans.length === 0 && (
                    <tr>
                      <td colSpan={8} className="text-center py-6 text-slate-500 font-mono">
                        No scans executed by this operator yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>

          {/* User Activity Audit Trail */}
          <Card title="Operator Audit Trail" subtitle="Verified security events and administrative actions">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Action</th>
                    <th className="py-2.5 px-3">Resource</th>
                    <th className="py-2.5 px-3">Details</th>
                    <th className="py-2.5 px-3 text-right">IP Address</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {recentActivity.map((a) => (
                    <tr key={a.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-2.5 px-3 text-slate-400 text-[11px] whitespace-nowrap">{formatDate(a.created_at)}</td>
                      <td className="py-2.5 px-3">
                        <Badge label={a.action} variant="cyan" size="xs" />
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">
                        {a.entity_type ? `${a.entity_type} #${a.entity_id || ''}` : '—'}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 max-w-sm truncate" title={a.details}>
                        {a.details || '—'}
                      </td>
                      <td className="py-2.5 px-3 text-slate-500 text-[11px] text-right whitespace-nowrap">
                        {a.ip_address || '127.0.0.1'}
                      </td>
                    </tr>
                  ))}
                  {recentActivity.length === 0 && (
                    <tr>
                      <td colSpan={5} className="text-center py-6 text-slate-500 font-mono">
                        No recorded audit activity for this operator.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>

          {/* Confirmation Modal */}
          <Modal
            isOpen={modalState.open}
            onClose={() => setModalState({ open: false, type: null, targetValue: null, loading: false, error: '' })}
            title={modalState.type === 'status' ? 'Confirm Status Modification' : 'Confirm Role Modification'}
          >
            <div className="space-y-4">
              <div className="p-3 bg-amber-950/30 border border-amber-500/30 rounded-lg flex items-start gap-3 text-xs text-amber-300 font-mono">
                <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <p className="font-bold">Privileged Administrative Operation</p>
                  <p className="mt-1 text-slate-300">
                    {modalState.type === 'status'
                      ? `Change activation status for ${account.email} to ${modalState.targetValue}?`
                      : `Alter role for ${account.email} to ${modalState.targetValue?.toUpperCase()}?`}
                  </p>
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
                  onClick={() => setModalState({ open: false, type: null, targetValue: null, loading: false, error: '' })}
                >
                  Cancel
                </Button>
                <Button
                  variant={modalState.targetValue === 'disabled' ? 'danger' : 'primary'}
                  size="sm"
                  loading={modalState.loading}
                  onClick={handleAction}
                >
                  Confirm
                </Button>
              </div>
            </div>
          </Modal>
        </>
      )}
    </div>
  );
}
