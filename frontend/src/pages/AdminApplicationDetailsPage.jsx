import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Layers,
  ArrowLeft,
  RefreshCw,
  Activity,
  UploadCloud,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Shield,
  FileCode,
  HardDrive,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import adminService from '../services/adminService';
import { formatDate, formatFileSize, getRiskScoreColor } from '../utils/formatters';

export default function AdminApplicationDetailsPage() {
  const { packageName } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchAppDetails = async () => {
    try {
      setLoading(true);
      setError('');
      const res = await adminService.getApplicationDetails(packageName);
      setData(res.data);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to retrieve application details.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAppDetails();
  }, [packageName]);

  const app = data?.application || {};
  const versions = data?.versions || [];
  const scans = data?.scans || [];

  return (
    <div className="space-y-6">
      <div>
        <Link to="/admin/applications">
          <Button variant="outline" size="sm">
            <ArrowLeft className="h-3.5 w-3.5 mr-1.5" /> Back to Applications
          </Button>
        </Link>
      </div>

      {loading && <LoadingSpinner message="Loading application version history and scans..." />}
      {error && <ErrorState title="Application Retrieval Error" message={error} onRetry={fetchAppDetails} />}

      {!loading && !error && data && (
        <>
          <PageHeader
            title={app.displayName || app.packageName || packageName}
            description={`Package Identifier: ${app.packageName || 'Not parsed'} • Total Versions: ${versions.length}`}
            badge={
              <Badge
                label={app.latestRiskLevel || 'UNSCORED'}
                variant={
                  app.latestRiskLevel === 'CRITICAL'
                    ? 'danger'
                    : app.latestRiskLevel === 'HIGH'
                    ? 'warning'
                    : 'info'
                }
              />
            }
            actions={
              <Button variant="outline" size="sm" onClick={fetchAppDetails}>
                <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Refresh
              </Button>
            }
          />

          {/* Quick Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <Card className="border-slate-800 p-4">
              <span className="text-[10px] font-mono uppercase text-slate-500">Total Uploads</span>
              <p className="text-2xl font-black font-mono text-emerald-400 mt-1">{app.totalUploads ?? 0}</p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">APK build archives</p>
            </Card>

            <Card className="border-slate-800 p-4">
              <span className="text-[10px] font-mono uppercase text-slate-500">Total Scans</span>
              <p className="text-2xl font-black font-mono text-cyan-400 mt-1">{app.totalScans ?? 0}</p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">Analyses performed</p>
            </Card>

            <Card className="border-slate-800 p-4">
              <span className="text-[10px] font-mono uppercase text-slate-500">Average Score</span>
              <p className="text-2xl font-black font-mono text-white mt-1">
                {app.avgSecurityScore !== null ? `${app.avgSecurityScore}/100` : '—'}
              </p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">Across completed scans</p>
            </Card>

            <Card className="border-slate-800 p-4">
              <span className="text-[10px] font-mono uppercase text-slate-500">Latest Risk Level</span>
              <p className={`text-2xl font-black font-mono mt-1 ${getRiskScoreColor(app.avgSecurityScore || 0)}`}>
                {app.latestRiskLevel || 'NONE'}
              </p>
              <p className="text-[10px] text-slate-500 font-mono mt-0.5">Most recent posture</p>
            </Card>
          </div>

          {/* Uploaded Versions Table */}
          <Card title="Uploaded Versions & Builds" subtitle="Historical APK artifacts registered for this application">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                    <th className="py-2.5 px-3">Filename</th>
                    <th className="py-2.5 px-3">Version Name</th>
                    <th className="py-2.5 px-3">Version Code</th>
                    <th className="py-2.5 px-3">File Size</th>
                    <th className="py-2.5 px-3">SHA256 Fingerprint</th>
                    <th className="py-2.5 px-3">Uploaded Date</th>
                    <th className="py-2.5 px-3 text-right">Uploader</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {versions.map((v) => (
                    <tr key={v.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-2.5 px-3 font-semibold text-slate-200">{v.originalFilename}</td>
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">{v.versionName || '1.0'}</td>
                      <td className="py-2.5 px-3 text-slate-400">{v.versionCode || '1'}</td>
                      <td className="py-2.5 px-3 text-slate-300">{formatFileSize(v.fileSize)}</td>
                      <td className="py-2.5 px-3 text-slate-500 text-[11px] font-mono truncate max-w-xs" title={v.sha256}>
                        {v.sha256?.substring(0, 16)}...
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[11px] whitespace-nowrap">{formatDate(v.createdAt)}</td>
                      <td className="py-2.5 px-3 text-right text-slate-300">
                        {v.uploadedBy?.name || v.uploadedBy?.email}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          {/* Application Scans History */}
          <Card title="Scan Executions" subtitle="Complete security evaluations across all versions">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                    <th className="py-2.5 px-3">Scan ID</th>
                    <th className="py-2.5 px-3">Target Version</th>
                    <th className="py-2.5 px-3">Execution Date</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3 text-center">Security Score</th>
                    <th className="py-2.5 px-3">Risk Level</th>
                    <th className="py-2.5 px-3 text-center">Findings</th>
                    <th className="py-2.5 px-3">Operator</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {scans.map((s) => (
                    <tr key={s.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">#{s.id}</td>
                      <td className="py-2.5 px-3 text-slate-300">{s.versionName || '1.0'}</td>
                      <td className="py-2.5 px-3 text-slate-400 text-[11px] whitespace-nowrap">{formatDate(s.createdAt)}</td>
                      <td className="py-2.5 px-3">
                        <Badge
                          label={s.status.toUpperCase()}
                          variant={s.status === 'completed' ? 'success' : s.status === 'failed' ? 'danger' : 'warning'}
                          size="xs"
                        />
                      </td>
                      <td className="py-2.5 px-3 text-center font-bold text-slate-200">
                        {s.securityScore !== null ? `${s.securityScore}/100` : '—'}
                      </td>
                      <td className="py-2.5 px-3">
                        {s.riskLevel ? (
                          <span className={`text-[11px] font-bold ${getRiskScoreColor(s.securityScore || 0)}`}>
                            {s.riskLevel}
                          </span>
                        ) : '—'}
                      </td>
                      <td className="py-2.5 px-3 text-center text-slate-300 font-bold">{s.vulnerabilityCount}</td>
                      <td className="py-2.5 px-3 text-slate-400">{s.user?.name || s.user?.email}</td>
                      <td className="py-2.5 px-3 text-right whitespace-nowrap">
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
                      <td colSpan={9} className="text-center py-6 text-slate-500 font-mono">
                        No scans executed for this application package yet.
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
