import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  History,
  Trash2,
  Eye,
  UploadCloud,
  FileCheck,
  RefreshCw,
  AlertTriangle,
  GitCompare,
  Search,
  Filter,
  ArrowUpDown,
  Layers,
  List,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import LoadingSpinner from '../components/LoadingSpinner';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';
import scanService from '../services/scanService';
import { formatDate, formatFileSize, getRiskScoreColor } from '../utils/formatters';

export default function ScanHistoryPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [deletingId, setDeletingId] = useState(null);

  // Sorting & Filtering
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL'); // ALL, completed, failed, in_progress
  const [sortBy, setSortBy] = useState('newest'); // newest, oldest, highest_risk, lowest_score, name
  const [viewMode, setViewMode] = useState('list'); // 'list' or 'portfolio'

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError('');
      const data = await scanService.getScans();
      setScans(data.scans || []);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load scan history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const handleDelete = async (scanId) => {
    if (!window.confirm(`Are you sure you want to delete scan record #${scanId}?`)) {
      return;
    }

    try {
      setDeletingId(scanId);
      await scanService.deleteScan(scanId);
      setScans((prev) => prev.filter((s) => s.id !== scanId));
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to delete scan record.');
    } finally {
      setDeletingId(null);
    }
  };

  // Filter scans
  const filteredScans = scans.filter((s) => {
    // Status filter
    if (statusFilter === 'completed' && s.status !== 'completed') return false;
    if (statusFilter === 'failed' && s.status !== 'failed') return false;
    if (
      statusFilter === 'in_progress' &&
      !['queued', 'extracting', 'analyzing', 'uploaded'].includes(s.status)
    )
      return false;

    // Search query
    const q = searchQuery.toLowerCase().trim();
    if (!q) return true;
    return (
      s.apkName?.toLowerCase().includes(q) ||
      s.packageName?.toLowerCase().includes(q) ||
      s.sha256?.toLowerCase().includes(q) ||
      String(s.id).includes(q)
    );
  });

  // Sort scans
  const sortedScans = [...filteredScans].sort((a, b) => {
    if (sortBy === 'newest') {
      return new Date(b.createdAt || b.startedAt) - new Date(a.createdAt || a.startedAt);
    }
    if (sortBy === 'oldest') {
      return new Date(a.createdAt || a.startedAt) - new Date(b.createdAt || b.startedAt);
    }
    if (sortBy === 'lowest_score') {
      return (a.securityScore ?? 100) - (b.securityScore ?? 100);
    }
    if (sortBy === 'highest_risk') {
      const riskWeight = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      const rA = riskWeight[a.riskLevel] || 0;
      const rB = riskWeight[b.riskLevel] || 0;
      return rB - rA;
    }
    if (sortBy === 'name') {
      return (a.apkName || '').localeCompare(b.apkName || '');
    }
    return 0;
  });

  const groupedApps = React.useMemo(() => {
    const groups = {};
    for (const scan of sortedScans) {
      const key = scan.packageName || scan.apkName || 'Unknown Application';
      if (!groups[key]) {
        groups[key] = {
          packageName: key,
          appName: scan.apkName,
          latestScan: scan,
          scans: [],
        };
      }
      groups[key].scans.push(scan);
    }
    return Object.values(groups);
  }, [sortedScans]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scan History & Application Portfolio"
        description="Comprehensive audit records of ingested Android applications, package versions, and security scores."
        badge={<Badge label={`${scans.length} Audits Recorded`} variant="primary" />}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex bg-slate-900 border border-slate-800 rounded-lg p-0.5 mr-1">
              <button
                type="button"
                onClick={() => setViewMode('list')}
                className={`flex items-center gap-1 px-2.5 py-1 text-xs font-mono rounded transition-colors ${
                  viewMode === 'list' ? 'bg-slate-800 text-cyan-400 font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <List className="h-3.5 w-3.5" /> List
              </button>
              <button
                type="button"
                onClick={() => setViewMode('portfolio')}
                className={`flex items-center gap-1 px-2.5 py-1 text-xs font-mono rounded transition-colors ${
                  viewMode === 'portfolio' ? 'bg-slate-800 text-cyan-400 font-bold' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Layers className="h-3.5 w-3.5" /> Portfolio
              </button>
            </div>
            <Link to="/scans/compare">
              <Button variant="outline" size="sm">
                <GitCompare className="h-3.5 w-3.5 mr-1.5 text-cyan-400" />
                Compare Scans
              </Button>
            </Link>
            <Button variant="outline" size="sm" onClick={fetchScans}>
              <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
              Refresh
            </Button>
            <Link to="/upload">
              <Button variant="primary" size="sm" className="shadow-cyber-glow">
                <UploadCloud className="h-4 w-4 mr-1.5" />
                Upload New APK
              </Button>
            </Link>
          </div>
        }
      />

      {loading && <LoadingSpinner message="Retrieving scan history records..." />}

      {error && <ErrorState title="History Load Error" message={error} onRetry={fetchScans} />}

      {!loading && !error && scans.length === 0 && (
        <EmptyState
          title="No APK Scans Found"
          description="You have not uploaded any Android application packages yet. Ingest an APK to initiate static security auditing."
          icon={FileCheck}
          actionLabel="Upload First APK"
          onAction={() => (window.location.href = '/upload')}
        />
      )}

      {!loading && !error && scans.length > 0 && (
        <div className="space-y-4">
          {/* Filter & Sort Controls */}
          <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row gap-3 items-center justify-between">
            <div className="relative w-full md:w-80">
              <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by APK name, package, SHA-256..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
              <div className="flex items-center gap-1.5 text-xs text-slate-400">
                <Filter className="h-3.5 w-3.5" />
                <span>Status:</span>
              </div>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="completed">Completed</option>
                <option value="in_progress">In Progress</option>
                <option value="failed">Failed</option>
              </select>

              <div className="flex items-center gap-1.5 text-xs text-slate-400 ml-1">
                <ArrowUpDown className="h-3.5 w-3.5" />
                <span>Sort By:</span>
              </div>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="newest">Newest First</option>
                <option value="oldest">Oldest First</option>
                <option value="lowest_score">Lowest Score First</option>
                <option value="highest_risk">Highest Risk First</option>
                <option value="name">APK Name</option>
              </select>

              {(searchQuery || statusFilter !== 'ALL' || sortBy !== 'newest') && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setSearchQuery('');
                    setStatusFilter('ALL');
                    setSortBy('newest');
                  }}
                  className="text-xs text-cyan-400 hover:text-cyan-300 py-1 px-2"
                >
                  Reset
                </Button>
              )}
            </div>
          </div>

          {viewMode === 'portfolio' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {groupedApps.map((group) => (
                <Card key={group.packageName} className="border-slate-800 space-y-4">
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="font-semibold text-sm text-slate-100 font-mono break-all">{group.packageName}</h3>
                      <p className="text-xs text-slate-400 font-sans mt-0.5">{group.appName}</p>
                    </div>
                    {group.latestScan.securityScore !== null ? (
                      <span className={`text-base font-extrabold font-mono ${getRiskScoreColor(group.latestScan.securityScore)}`}>
                        {group.latestScan.securityScore}/100
                      </span>
                    ) : (
                      <span className="text-slate-600 font-mono text-sm">--</span>
                    )}
                  </div>

                  <div className="flex items-center justify-between text-xs font-mono pt-2 border-t border-slate-800/80">
                    <span className="text-slate-400">{group.scans.length} Scan Build(s)</span>
                    <Badge
                      label={group.latestScan.riskLevel || group.latestScan.status}
                      variant={group.latestScan.riskLevel === 'CRITICAL' ? 'danger' : group.latestScan.riskLevel === 'HIGH' ? 'warning' : 'info'}
                      size="xs"
                    />
                  </div>

                  <div className="space-y-1.5 pt-1">
                    <p className="text-[10px] font-mono text-slate-500 uppercase">Build History</p>
                    <div className="max-h-36 overflow-y-auto space-y-1">
                      {group.scans.map((s) => (
                        <div key={s.id} className="flex items-center justify-between text-xs p-2 rounded bg-slate-950 border border-slate-800/60 font-mono">
                          <div className="flex items-center gap-2">
                            <span className="text-cyan-400 font-bold">#{s.id}</span>
                            <span className="text-slate-300">v{s.versionName || '1.0'}</span>
                            <span className="text-slate-500 text-[10px]">{formatDate(s.completedAt || s.createdAt)}</span>
                          </div>
                          <Link to={`/scans/${s.id}`} className="text-cyan-400 hover:text-cyan-300 text-[11px] font-semibold">
                            View →
                          </Link>
                        </div>
                      ))}
                    </div>
                  </div>

                  {group.scans.length > 1 && (
                    <Link to={`/scans/compare?baseScanId=${group.scans[1].id}&targetScanId=${group.scans[0].id}`} className="block">
                      <Button variant="outline" size="xs" className="w-full justify-center">
                        <GitCompare className="h-3 w-3 mr-1 text-cyan-400" />
                        Compare Latest 2 Builds
                      </Button>
                    </Link>
                  )}
                </Card>
              ))}
            </div>
          ) : (
            /* Scans Table */
            <Card className="border-slate-800 p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase text-[10px]">
                    <th className="py-3 px-4">Audit ID</th>
                    <th className="py-3 px-4">Target Application</th>
                    <th className="py-3 px-4">Version</th>
                    <th className="py-3 px-4">Size</th>
                    <th className="py-3 px-4">Assessment Date</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Score</th>
                    <th className="py-3 px-4">Threat Vectors</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {sortedScans.length === 0 ? (
                    <tr>
                      <td colSpan={9} className="py-8 text-center text-slate-500">
                        No scans matched the selected search or filter criteria.
                      </td>
                    </tr>
                  ) : (
                    sortedScans.map((scan) => (
                      <tr key={scan.id} className="hover:bg-slate-900/40 transition-colors">
                        <td className="py-3 px-4 text-cyan-400 font-bold">#{scan.id}</td>
                        <td className="py-3 px-4 font-sans font-medium text-slate-200">
                          <Link to={`/scans/${scan.id}`} className="hover:text-cyan-400">
                            {scan.packageName || scan.apkName}
                          </Link>
                          {scan.packageName && (
                            <span className="text-[10px] text-slate-500 font-mono block">
                              {scan.apkName}
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-300">
                          {scan.versionName ? `v${scan.versionName}` : '1.0'}
                        </td>
                        <td className="py-3 px-4 text-slate-400">{formatFileSize(scan.fileSize)}</td>
                        <td className="py-3 px-4 text-slate-400">
                          {formatDate(scan.completedAt || scan.createdAt)}
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${
                              scan.status === 'completed'
                                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                                : scan.status === 'failed'
                                ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                                : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 animate-pulse'
                            }`}
                          >
                            {scan.status}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-bold">
                          {scan.securityScore !== null ? (
                            <span className={getRiskScoreColor(scan.securityScore)}>
                              {scan.securityScore}/100
                            </span>
                          ) : (
                            <span className="text-slate-600">--</span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          {scan.status === 'completed' ? (
                            <div className="flex items-center gap-1.5">
                              {scan.criticalCount > 0 && (
                                <span className="px-1.5 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-500/30 text-[10px] font-bold">
                                  {scan.criticalCount}C
                                </span>
                              )}
                              {scan.highCount > 0 && (
                                <span className="px-1.5 py-0.5 rounded bg-orange-950/40 text-orange-400 border border-orange-500/30 text-[10px] font-bold">
                                  {scan.highCount}H
                                </span>
                              )}
                              {scan.mediumCount > 0 && (
                                <span className="px-1.5 py-0.5 rounded bg-amber-950/40 text-amber-300 border border-amber-500/30 text-[10px]">
                                  {scan.mediumCount}M
                                </span>
                              )}
                              {scan.lowCount > 0 && (
                                <span className="px-1.5 py-0.5 rounded bg-cyan-950/40 text-cyan-400 border border-cyan-500/30 text-[10px]">
                                  {scan.lowCount}L
                                </span>
                              )}
                              {scan.criticalCount === 0 &&
                                scan.highCount === 0 &&
                                scan.mediumCount === 0 &&
                                scan.lowCount === 0 && (
                                  <span className="text-[10px] text-emerald-400 font-bold">Clean</span>
                                )}
                            </div>
                          ) : (
                            <span className="text-slate-600 text-[10px]">--</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            <Link to={`/scans/${scan.id}`}>
                              <Button variant="ghost" size="sm" title="View Assessment Details">
                                <Eye className="h-3.5 w-3.5" />
                              </Button>
                            </Link>
                            <Button
                              variant="ghost"
                              size="sm"
                              title="Delete Scan Record"
                              disabled={deletingId === scan.id}
                              onClick={() => handleDelete(scan.id)}
                              className="hover:text-red-400"
                            >
                              <Trash2 className="h-3.5 w-3.5 text-slate-500 hover:text-red-400" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Card>
          )}
        </div>
      )}
    </div>
  );
}
