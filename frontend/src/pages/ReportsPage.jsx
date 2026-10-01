import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  FileText,
  FileDown,
  FileJson,
  FileSpreadsheet,
  Download,
  Eye,
  RefreshCw,
  Search,
  CheckCircle2,
  ShieldAlert,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import LoadingSpinner from '../components/LoadingSpinner';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';
import scanService from '../services/scanService';
import { formatDate, getRiskScoreColor } from '../utils/formatters';

export default function ReportsPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [downloadingId, setDownloadingId] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError('');
      const data = await scanService.getScans();
      const completed = (data.scans || []).filter((s) => s.status === 'completed');
      setScans(completed);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to retrieve assessment reports.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  const handleDownload = async (scanId, type) => {
    const key = `${scanId}_${type}`;
    try {
      setDownloadingId(key);
      if (type === 'pdf') {
        await scanService.downloadPdf(scanId, `security_report_scan_${scanId}.pdf`);
      } else if (type === 'json') {
        await scanService.downloadJson(scanId, `security_report_scan_${scanId}.json`);
      } else if (type === 'csv') {
        await scanService.downloadCsv(scanId, `vulnerabilities_scan_${scanId}.csv`);
      }
    } catch (err) {
      alert(err.response?.data?.message || `Failed to download ${type.toUpperCase()} report.`);
    } finally {
      setDownloadingId(null);
    }
  };

  const filteredScans = scans.filter((s) => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return true;
    return (
      s.apkName?.toLowerCase().includes(q) ||
      s.packageName?.toLowerCase().includes(q) ||
      String(s.id).includes(q)
    );
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Audit Reports & Documentation"
        description="Download publication-quality PDF assessment reports, sanitized machine-readable JSON, and findings CSV spreadsheets."
        badge={<Badge label={`${scans.length} Reports Ready`} variant="primary" />}
        actions={
          <Button variant="outline" size="sm" onClick={fetchScans}>
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
            Refresh
          </Button>
        }
      />

      {loading && <LoadingSpinner message="Retrieving publication-grade security reports..." />}

      {error && <ErrorState title="Report Access Error" message={error} onRetry={fetchScans} />}

      {!loading && !error && scans.length === 0 && (
        <EmptyState
          title="No Assessment Reports Available"
          description="Reports are generated automatically once an APK static security scan completes."
          icon={FileText}
          actionLabel="Upload APK to Scan"
          onAction={() => (window.location.href = '/upload')}
        />
      )}

      {!loading && !error && scans.length > 0 && (
        <div className="space-y-4">
          {/* Search Bar */}
          <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
            <div className="relative w-full md:w-80">
              <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search reports by package, APK name..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
            <span className="text-xs font-mono text-slate-400 hidden sm:block">
              {filteredScans.length} of {scans.length} reports listed
            </span>
          </div>

          {/* Reports Table */}
          <Card className="border-slate-800 p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase text-[10px]">
                    <th className="py-3 px-4">Audit ID</th>
                    <th className="py-3 px-4">Target Application</th>
                    <th className="py-3 px-4">Version</th>
                    <th className="py-3 px-4">Assessment Date</th>
                    <th className="py-3 px-4">Security Score</th>
                    <th className="py-3 px-4">Risk Level</th>
                    <th className="py-3 px-4 text-right">Export Formats</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredScans.map((scan) => (
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
                      <td className="py-3 px-4 text-slate-400">
                        {formatDate(scan.completedAt || scan.createdAt)}
                      </td>
                      <td className="py-3 px-4 font-bold">
                        <span className={getRiskScoreColor(scan.securityScore)}>
                          {scan.securityScore}/100
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <Badge severity={scan.riskLevel} label={scan.riskLevel} />
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            loading={downloadingId === `${scan.id}_pdf`}
                            onClick={() => handleDownload(scan.id, 'pdf')}
                            className="border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 text-xs py-1"
                          >
                            <FileDown className="h-3.5 w-3.5 mr-1" />
                            PDF
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            loading={downloadingId === `${scan.id}_json`}
                            onClick={() => handleDownload(scan.id, 'json')}
                            className="text-xs text-slate-300 hover:text-cyan-300 py-1"
                          >
                            <FileJson className="h-3.5 w-3.5 mr-1" />
                            JSON
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            loading={downloadingId === `${scan.id}_csv`}
                            onClick={() => handleDownload(scan.id, 'csv')}
                            className="text-xs text-slate-300 hover:text-cyan-300 py-1"
                          >
                            <FileSpreadsheet className="h-3.5 w-3.5 mr-1" />
                            CSV
                          </Button>
                          <Link to={`/scans/${scan.id}`}>
                            <Button variant="ghost" size="sm" title="View Audit Details">
                              <Eye className="h-3.5 w-3.5 text-slate-400 hover:text-slate-200" />
                            </Button>
                          </Link>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
