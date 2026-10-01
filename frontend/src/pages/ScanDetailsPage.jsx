import React, { useState, useEffect, useRef } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  HardDrive,
  Calendar,
  Hash,
  Play,
  ArrowLeft,
  Trash2,
  Info,
  Clock,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Cpu,
  Layers,
  Activity,
  Lock,
  Globe,
  Key,
  Search,
  Filter,
  Copy,
  Check,
  ExternalLink,
  Code,
  FileCode,
  Download,
  FileDown,
  GitCompare,
  FileSpreadsheet,
  FileJson,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from 'recharts';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import scanService from '../services/scanService';
import { formatDate, formatFileSize, getRiskScoreColor, getSeverityColor } from '../utils/formatters';

export default function ScanDetailsPage() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [startingScan, setStartingScan] = useState(false);
  const [error, setError] = useState('');
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [activeTab, setActiveTab] = useState('findings'); // 'findings', 'secrets', 'network', 'permissions', 'components'

  // Export loading states
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [downloadingJson, setDownloadingJson] = useState(false);
  const [downloadingCsv, setDownloadingCsv] = useState(false);

  // Filtering states
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [copiedSecretId, setCopiedSecretId] = useState(null);

  const pollingRef = useRef(null);

  const fetchScanDetails = async (isPolling = false) => {
    try {
      if (!isPolling) setLoading(true);
      const data = await scanService.getScan(id);
      setScanData(data);
      if (!isPolling) setLoading(false);
    } catch (err) {
      if (!isPolling) {
        setError(err.response?.data?.message || `Failed to retrieve scan record #${id}.`);
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    fetchScanDetails();

    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [id]);

  // Set up polling while scan is running
  useEffect(() => {
    const status = scanData?.scan?.status;
    if (status === 'queued' || status === 'extracting' || status === 'analyzing') {
      if (!pollingRef.current) {
        pollingRef.current = setInterval(() => {
          fetchScanDetails(true);
        }, 1500);
      }
    } else {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    }
  }, [scanData?.scan?.status]);

  const handleStartScan = async () => {
    try {
      setStartingScan(true);
      setError('');
      await scanService.startScan(id);
      await fetchScanDetails(true);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to initiate security scan.');
    } finally {
      setStartingScan(false);
    }
  };

  const handleDelete = async () => {
    if (!window.confirm(`Are you sure you want to permanently delete scan #${id}?`)) {
      return;
    }
    try {
      await scanService.deleteScan(id);
      navigate('/scans');
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to delete scan.');
    }
  };

  const handleDownloadPdf = async () => {
    try {
      setDownloadingPdf(true);
      await scanService.downloadPdf(id, `security_report_scan_${id}.pdf`);
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to download PDF report.');
    } finally {
      setDownloadingPdf(false);
    }
  };

  const handleDownloadJson = async () => {
    try {
      setDownloadingJson(true);
      await scanService.downloadJson(id, `security_report_scan_${id}.json`);
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to export JSON report.');
    } finally {
      setDownloadingJson(false);
    }
  };

  const handleDownloadCsv = async () => {
    try {
      setDownloadingCsv(true);
      await scanService.downloadCsv(id, `vulnerabilities_scan_${id}.csv`);
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to export CSV report.');
    } finally {
      setDownloadingCsv(false);
    }
  };

  const handleCopy = (text, itemKey) => {
    navigator.clipboard.writeText(text);
    setCopiedSecretId(itemKey);
    setTimeout(() => setCopiedSecretId(null), 2000);
  };

  const scan = scanData?.scan;
  const vulnerabilities = scanData?.vulnerabilities || [];
  const permissions = scanData?.permissions || [];
  const components = scanData?.components || [];
  const networkFindings = scanData?.networkFindings || [];
  const secrets = scanData?.secrets || [];

  const counts = {
    critical: vulnerabilities.filter((v) => v.severity === 'CRITICAL').length,
    high: vulnerabilities.filter((v) => v.severity === 'HIGH').length,
    medium: vulnerabilities.filter((v) => v.severity === 'MEDIUM').length,
    low: vulnerabilities.filter((v) => v.severity === 'LOW').length,
    informational: vulnerabilities.filter((v) => v.severity === 'INFORMATIONAL').length,
  };

  // Distribution chart data
  const severityChartData = [
    { name: 'Critical', count: counts.critical, color: '#ef4444' },
    { name: 'High', count: counts.high, color: '#f97316' },
    { name: 'Medium', count: counts.medium, color: '#eab308' },
    { name: 'Low', count: counts.low, color: '#06b6d4' },
  ];

  // Derive unique categories for filter dropdown
  const uniqueCategories = Array.from(new Set(vulnerabilities.map((v) => v.category).filter(Boolean))).sort();

  // Category chart data
  const categoryCounts = {};
  vulnerabilities.forEach((v) => {
    const c = v.category || 'Other';
    categoryCounts[c] = (categoryCounts[c] || 0) + 1;
  });
  const categoryChartData = Object.entries(categoryCounts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  // Filter vulnerabilities
  const filteredVulnerabilities = vulnerabilities.filter((v) => {
    const matchesSeverity = severityFilter === 'ALL' || v.severity === severityFilter;
    const matchesCategory = categoryFilter === 'ALL' || v.category === categoryFilter;
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      v.title?.toLowerCase().includes(q) ||
      v.description?.toLowerCase().includes(q) ||
      v.category?.toLowerCase().includes(q) ||
      v.cwe?.toLowerCase().includes(q) ||
      v.owasp_category?.toLowerCase().includes(q) ||
      v.location?.toLowerCase().includes(q);

    return matchesSeverity && matchesCategory && matchesSearch;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
        <Link to="/scans" className="hover:text-cyan-400 flex items-center gap-1">
          <ArrowLeft className="h-3 w-3" /> Back to Scan History
        </Link>
        <span>/</span>
        <span className="text-slate-200">Scan #{id}</span>
      </div>

      <PageHeader
        title={`Security Assessment #${id}`}
        description="Comprehensive automated Android static security analysis, risk telemetry, and remediation lifecycle."
        badge={
          scan?.status ? (
            <Badge
              label={`STATUS: ${scan.status.toUpperCase()}`}
              variant={scan.status === 'completed' ? 'success' : scan.status === 'failed' ? 'danger' : 'warning'}
            />
          ) : null
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {scan?.status === 'completed' && (
              <>
                <Link to={`/scans/compare?targetScanId=${id}`}>
                  <Button variant="outline" size="sm" title="Compare with another scan">
                    <GitCompare className="h-3.5 w-3.5 mr-1.5 text-cyan-400" />
                    Compare
                  </Button>
                </Link>
                <Button
                  variant="outline"
                  size="sm"
                  loading={downloadingPdf}
                  onClick={handleDownloadPdf}
                  className="border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10"
                >
                  <FileDown className="h-3.5 w-3.5 mr-1.5" />
                  PDF Report
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  loading={downloadingJson}
                  onClick={handleDownloadJson}
                  className="text-xs text-slate-300 hover:text-cyan-300"
                >
                  <FileJson className="h-3.5 w-3.5 mr-1" />
                  JSON
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  loading={downloadingCsv}
                  onClick={handleDownloadCsv}
                  className="text-xs text-slate-300 hover:text-cyan-300"
                >
                  <FileSpreadsheet className="h-3.5 w-3.5 mr-1" />
                  CSV
                </Button>
              </>
            )}

            <Button
              variant="outline"
              size="sm"
              onClick={handleDelete}
              className="border-red-500/30 text-red-400 hover:bg-red-500/10"
            >
              <Trash2 className="h-3.5 w-3.5 mr-1.5" />
              Delete
            </Button>
          </div>
        }
      />

      {loading && <LoadingSpinner message={`Loading audit record #${id}...`} />}

      {error && <ErrorState title="Audit Notification" message={error} onRetry={() => fetchScanDetails()} />}

      {!loading && scan && (
        <>
          {/* Unstarted / Uploaded State */}
          {scan.status === 'uploaded' && (
            <Card title="Initiate Static Analysis" subtitle="Run automated static audit against this APK" className="border-slate-800">
              <div className="py-8 px-4 text-center max-w-xl mx-auto space-y-4">
                <div className="h-12 w-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mx-auto">
                  <Play className="h-6 w-6 ml-0.5" />
                </div>
                <div>
                  <h4 className="text-base font-semibold text-slate-100">Ready for Deep Static Analysis</h4>
                  <p className="mt-1 text-xs text-slate-400">
                    The package archive integrity is validated and ready for multi-stage static analysis. Click below to launch the engine.
                  </p>
                </div>
                <div>
                  <Button
                    variant="primary"
                    size="lg"
                    loading={startingScan}
                    onClick={handleStartScan}
                    className="shadow-cyber-glow"
                  >
                    <Play className="h-4 w-4 mr-2" />
                    Start Deep Security Scan
                  </Button>
                </div>
              </div>
            </Card>
          )}

          {/* Running / Polling State */}
          {(scan.status === 'queued' || scan.status === 'extracting' || scan.status === 'analyzing') && (
            <Card className="border-cyan-500/30 bg-cyan-950/10 py-8 px-4 text-center">
              <div className="max-w-md mx-auto space-y-4">
                <div className="h-12 w-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mx-auto animate-pulse">
                  <Cpu className="h-6 w-6" />
                </div>
                <div>
                  <h4 className="text-base font-semibold text-slate-100 uppercase tracking-wide">
                    Analysis In Progress: {scan.status}
                  </h4>
                  <p className="mt-1 text-xs text-slate-400">
                    Decompiling DEX string pools, analyzing manifest permissions, detecting exposed secrets, and evaluating risk score...
                  </p>
                </div>
                <div className="space-y-1.5">
                  <div className="flex justify-between text-xs font-mono text-cyan-400">
                    <span>Engine Stage: {scan.status}</span>
                    <span>{scan.progress || 0}%</span>
                  </div>
                  <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-cyan-500 transition-all duration-300"
                      style={{ width: `${scan.progress || 10}%` }}
                    />
                  </div>
                </div>
              </div>
            </Card>
          )}

          {/* Completed State: Real Security Score & Findings */}
          {scan.status === 'completed' && (
            <>
              {/* Executive Summary Card */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Score Gauge Card */}
                <Card className="flex flex-col items-center justify-center text-center p-6 border-slate-800">
                  <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-2">
                    Security Score
                  </span>
                  <div className="flex items-baseline gap-1">
                    <span className={`text-6xl font-black font-mono ${getRiskScoreColor(scan.securityScore)}`}>
                      {scan.securityScore}
                    </span>
                    <span className="text-xl font-bold text-slate-400">/ 100</span>
                  </div>
                  <div className="mt-3">
                    <Badge severity={scan.riskLevel} size="md" label={`RISK: ${scan.riskLevel}`} />
                  </div>
                  <p className="mt-3 text-[11px] text-slate-400 max-w-xs leading-relaxed">
                    Deterministic score derived from verified vulnerability deductions (100 baseline).
                  </p>
                </Card>

                {/* Executive Breakdown Overview */}
                <Card title="Executive Threat Telemetry" subtitle="Summary of verified static analysis vectors" className="lg:col-span-2">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-3">
                    <div
                      onClick={() => { setSeverityFilter('CRITICAL'); setActiveTab('findings'); }}
                      className="p-3 rounded-lg bg-red-950/20 border border-red-500/30 text-center cursor-pointer hover:border-red-400 transition-colors"
                    >
                      <span className="text-[10px] font-mono text-red-400 block uppercase">Critical</span>
                      <span className="text-2xl font-bold text-red-400 font-mono mt-0.5 block">{counts.critical}</span>
                    </div>

                    <div
                      onClick={() => { setSeverityFilter('HIGH'); setActiveTab('findings'); }}
                      className="p-3 rounded-lg bg-orange-950/20 border border-orange-500/30 text-center cursor-pointer hover:border-orange-400 transition-colors"
                    >
                      <span className="text-[10px] font-mono text-orange-400 block uppercase">High</span>
                      <span className="text-2xl font-bold text-orange-400 font-mono mt-0.5 block">{counts.high}</span>
                    </div>

                    <div
                      onClick={() => { setSeverityFilter('MEDIUM'); setActiveTab('findings'); }}
                      className="p-3 rounded-lg bg-amber-950/20 border border-amber-500/30 text-center cursor-pointer hover:border-amber-400 transition-colors"
                    >
                      <span className="text-[10px] font-mono text-amber-400 block uppercase">Medium</span>
                      <span className="text-2xl font-bold text-amber-400 font-mono mt-0.5 block">{counts.medium}</span>
                    </div>

                    <div
                      onClick={() => { setSeverityFilter('LOW'); setActiveTab('findings'); }}
                      className="p-3 rounded-lg bg-cyan-950/20 border border-cyan-500/30 text-center cursor-pointer hover:border-cyan-400 transition-colors"
                    >
                      <span className="text-[10px] font-mono text-cyan-400 block uppercase">Low</span>
                      <span className="text-2xl font-bold text-cyan-400 font-mono mt-0.5 block">{counts.low}</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-3 mt-3 pt-3 border-t border-slate-800 text-xs font-mono">
                    <div className="p-2 rounded bg-slate-900 border border-slate-800 text-center">
                      <span className="text-[10px] text-amber-400 block uppercase">Secrets</span>
                      <span className="text-base font-bold text-slate-100">{secrets.length}</span>
                    </div>
                    <div className="p-2 rounded bg-slate-900 border border-slate-800 text-center">
                      <span className="text-[10px] text-cyan-400 block uppercase">Network Issues</span>
                      <span className="text-base font-bold text-slate-100">{networkFindings.length}</span>
                    </div>
                    <div className="p-2 rounded bg-slate-900 border border-slate-800 text-center">
                      <span className="text-[10px] text-slate-400 block uppercase">Components</span>
                      <span className="text-base font-bold text-slate-100">{components.length}</span>
                    </div>
                  </div>
                </Card>
              </div>

              {/* Visual Charts Row */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Card title="Severity Distribution" subtitle="Click any bar to filter findings by risk tier">
                  <div className="h-48 mt-2">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={severityChartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                        <XAxis dataKey="name" stroke="#64748b" fontSize={10} tickLine={false} />
                        <YAxis stroke="#64748b" fontSize={10} tickLine={false} allowDecimals={false} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#0f172a',
                            borderColor: '#334155',
                            borderRadius: '8px',
                            fontSize: '11px',
                            color: '#f8fafc',
                          }}
                        />
                        <Bar
                          dataKey="count"
                          radius={[4, 4, 0, 0]}
                          onClick={(data) => {
                            if (data?.name) {
                              setSeverityFilter(data.name.toUpperCase());
                              setActiveTab('findings');
                            }
                          }}
                          className="cursor-pointer"
                        >
                          {severityChartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </Card>

                <Card title="Top Vulnerability Categories" subtitle="Distribution across architectural security domains">
                  <div className="h-48 mt-2">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={categoryChartData} layout="vertical" margin={{ top: 5, right: 10, left: 30, bottom: 0 }}>
                        <XAxis type="number" stroke="#64748b" fontSize={10} tickLine={false} allowDecimals={false} />
                        <YAxis type="category" dataKey="name" stroke="#94a3b8" fontSize={9} tickLine={false} width={80} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#0f172a',
                            borderColor: '#334155',
                            borderRadius: '8px',
                            fontSize: '11px',
                            color: '#f8fafc',
                          }}
                        />
                        <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </Card>
              </div>

              {/* Application Profile Card */}
              <Card title="Application Security Profile" subtitle="Package identity, versions, and archive fingerprint">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-1">
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-[10px] font-mono text-slate-400 block uppercase">Package Name</span>
                    <span className="text-xs font-semibold text-slate-100 mt-1 block truncate font-mono">
                      {scan.packageName || scan.apkName}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-[10px] font-mono text-slate-400 block uppercase">Version</span>
                    <span className="text-xs font-semibold text-slate-100 mt-1 block font-mono">
                      v{scan.versionName || '1.0'} ({scan.versionCode || 1})
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-[10px] font-mono text-slate-400 block uppercase">Archive Size</span>
                    <span className="text-xs font-semibold text-slate-100 mt-1 block font-mono">
                      {formatFileSize(scan.fileSize)}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <span className="text-[10px] font-mono text-slate-400 block uppercase">Completed Date</span>
                    <span className="text-xs font-semibold text-slate-100 mt-1 block">
                      {formatDate(scan.completedAt || scan.createdAt)}
                    </span>
                  </div>
                </div>

                <div className="mt-3 p-3 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-[10px] font-mono text-slate-400 block uppercase mb-1">
                    SHA-256 Checksum
                  </span>
                  <span className="text-xs font-mono text-cyan-300 break-all select-all">
                    {scan.sha256}
                  </span>
                </div>
              </Card>

              {/* Navigation Tabs */}
              <div className="flex flex-wrap border-b border-slate-800 gap-2 sm:gap-4 text-sm font-medium">
                <button
                  onClick={() => setActiveTab('findings')}
                  className={`pb-3 border-b-2 transition-colors flex items-center gap-2 ${
                    activeTab === 'findings'
                      ? 'border-cyan-400 text-cyan-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <ShieldAlert className="h-4 w-4" />
                  Security Findings ({vulnerabilities.length})
                </button>
                <button
                  onClick={() => setActiveTab('secrets')}
                  className={`pb-3 border-b-2 transition-colors flex items-center gap-2 ${
                    activeTab === 'secrets'
                      ? 'border-cyan-400 text-cyan-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Key className="h-4 w-4" />
                  Exposed Secrets ({secrets.length})
                </button>
                <button
                  onClick={() => setActiveTab('network')}
                  className={`pb-3 border-b-2 transition-colors flex items-center gap-2 ${
                    activeTab === 'network'
                      ? 'border-cyan-400 text-cyan-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Globe className="h-4 w-4" />
                  Network Intelligence ({networkFindings.length})
                </button>
                <button
                  onClick={() => setActiveTab('permissions')}
                  className={`pb-3 border-b-2 transition-colors flex items-center gap-2 ${
                    activeTab === 'permissions'
                      ? 'border-cyan-400 text-cyan-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Lock className="h-4 w-4" />
                  Permissions ({permissions.length})
                </button>
                <button
                  onClick={() => setActiveTab('components')}
                  className={`pb-3 border-b-2 transition-colors flex items-center gap-2 ${
                    activeTab === 'components'
                      ? 'border-cyan-400 text-cyan-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Layers className="h-4 w-4" />
                  Components ({components.length})
                </button>
              </div>

              {/* Tab 1: Vulnerabilities */}
              {activeTab === 'findings' && (
                <div className="space-y-4">
                  {/* Filters Bar */}
                  <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col md:flex-row gap-3 items-center justify-between">
                    <div className="relative w-full md:w-80">
                      <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                      <input
                        type="text"
                        placeholder="Search findings by title, CWE, OWASP..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                      />
                    </div>

                    <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
                      <div className="flex items-center gap-1.5 text-xs text-slate-400">
                        <Filter className="h-3.5 w-3.5" />
                        <span>Severity:</span>
                      </div>
                      <select
                        value={severityFilter}
                        onChange={(e) => setSeverityFilter(e.target.value)}
                        className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                      >
                        <option value="ALL">All Severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                        <option value="INFORMATIONAL">Informational</option>
                      </select>

                      <div className="flex items-center gap-1.5 text-xs text-slate-400 ml-1">
                        <span>Category:</span>
                      </div>
                      <select
                        value={categoryFilter}
                        onChange={(e) => setCategoryFilter(e.target.value)}
                        className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 max-w-[180px] truncate"
                      >
                        <option value="ALL">All Categories</option>
                        {uniqueCategories.map((c) => (
                          <option key={c} value={c}>
                            {c}
                          </option>
                        ))}
                      </select>

                      {(searchQuery || severityFilter !== 'ALL' || categoryFilter !== 'ALL') && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            setSearchQuery('');
                            setSeverityFilter('ALL');
                            setCategoryFilter('ALL');
                          }}
                          className="text-xs text-cyan-400 hover:text-cyan-300 py-1 px-2"
                        >
                          Clear
                        </Button>
                      )}
                    </div>
                  </div>

                  {filteredVulnerabilities.length === 0 ? (
                    <Card className="text-center py-10 text-slate-400 text-xs">
                      No security vulnerabilities matched the selected filters.
                    </Card>
                  ) : (
                    filteredVulnerabilities.map((finding) => {
                      const isExpanded = expandedFinding === finding.id;

                      return (
                        <div
                          key={finding.id}
                          className={`rounded-xl border transition-all ${
                            isExpanded ? 'bg-slate-900 border-slate-700 shadow-cyber-card' : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                          }`}
                        >
                          <div
                            className="p-4 flex items-start justify-between cursor-pointer"
                            onClick={() => setExpandedFinding(isExpanded ? null : finding.id)}
                          >
                            <div className="flex items-start gap-3">
                              <Badge severity={finding.severity} />
                              <div>
                                <div className="flex items-center gap-2">
                                  <h4 className="text-sm font-semibold text-slate-100">{finding.title}</h4>
                                  {finding.status && finding.status !== 'OPEN' && (
                                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/30 text-amber-300 border border-amber-500/20">
                                      {finding.status}
                                    </span>
                                  )}
                                </div>
                                <div className="flex flex-wrap items-center gap-2 mt-1.5 text-xs text-slate-400 font-mono">
                                  <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                                    {finding.category}
                                  </span>
                                  {finding.cwe && <span>&bull; {finding.cwe}</span>}
                                  {finding.owasp_category && (
                                    <span className="text-cyan-400">&bull; {finding.owasp_category}</span>
                                  )}
                                  {finding.confidence && (
                                    <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                                      Confidence: {finding.confidence}
                                    </span>
                                  )}
                                  {finding.analyzer && (
                                    <span className="text-[10px] text-cyan-400/80 font-mono">
                                      [{finding.analyzer}]
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>

                            <div className="flex items-center gap-2 shrink-0">
                              <Link
                                to={`/scans/${id}/findings/${finding.id}`}
                                onClick={(e) => e.stopPropagation()}
                                className="text-xs text-cyan-400 hover:text-cyan-300 font-mono px-2 py-1 rounded hover:bg-slate-800 transition-colors"
                              >
                                Triage &amp; Details &rarr;
                              </Link>
                              <button className="text-slate-400 hover:text-slate-200 p-1">
                                {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                              </button>
                            </div>
                          </div>

                          {isExpanded && (
                            <div className="px-4 pb-5 pt-1 border-t border-slate-800/60 space-y-4 text-xs">
                              <div>
                                <p className="font-semibold text-slate-300 uppercase tracking-wider text-[10px] mb-1 font-mono">
                                  Description
                                </p>
                                <p className="text-slate-300 leading-relaxed">{finding.description}</p>
                              </div>

                              {finding.evidence && (
                                <div>
                                  <p className="font-semibold text-slate-300 uppercase tracking-wider text-[10px] mb-1 font-mono">
                                    Observed Evidence
                                  </p>
                                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-cyan-300 break-all select-all">
                                    {finding.evidence}
                                  </div>
                                </div>
                              )}

                              {finding.location && (
                                <div>
                                  <p className="font-semibold text-slate-300 uppercase tracking-wider text-[10px] mb-1 font-mono">
                                    Artifact Location
                                  </p>
                                  <p className="font-mono text-slate-400">{finding.location}</p>
                                </div>
                              )}

                              {finding.impact && (
                                <div>
                                  <p className="font-semibold text-slate-300 uppercase tracking-wider text-[10px] mb-1 font-mono">
                                    Security Impact
                                  </p>
                                  <p className="text-slate-300 leading-relaxed">{finding.impact}</p>
                                </div>
                              )}

                              {finding.recommendation && (
                                <div className="p-3 rounded-lg bg-cyan-950/20 border border-cyan-500/20">
                                  <p className="font-semibold text-cyan-300 uppercase tracking-wider text-[10px] mb-1 font-mono">
                                    Remediation Guidance
                                  </p>
                                  <p className="text-slate-300 leading-relaxed">{finding.recommendation}</p>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              )}

              {/* Tab 2: Secrets */}
              {activeTab === 'secrets' && (
                <div className="space-y-4">
                  <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 flex items-start gap-3">
                    <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <h4 className="text-sm font-semibold text-amber-300">Exposed Secrets Advisory</h4>
                      <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                        Hardcoded credentials inside compiled Android binaries and assets can be extracted by reverse engineering tools. All detected secrets have been masked to prevent unauthorized disclosure. <strong>Rotate all compromised API keys and secrets immediately.</strong>
                      </p>
                    </div>
                  </div>

                  {secrets.length === 0 ? (
                    <Card className="text-center py-10 text-slate-400 text-xs">
                      No hardcoded API keys, tokens, or credentials detected across DEX string pools and assets.
                    </Card>
                  ) : (
                    <Card className="p-0 overflow-hidden border-slate-800">
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs font-mono">
                          <thead>
                            <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase text-[10px]">
                              <th className="py-3 px-4">Secret Classification</th>
                              <th className="py-3 px-4">Severity</th>
                              <th className="py-3 px-4">Origin / File Location</th>
                              <th className="py-3 px-4">Masked Credential Evidence</th>
                              <th className="py-3 px-4 text-right">Actions</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/60">
                            {secrets.map((s, idx) => (
                              <tr key={s.id || idx} className="hover:bg-slate-900/30">
                                <td className="py-3 px-4 text-slate-200 font-semibold">{s.secret_type}</td>
                                <td className="py-3 px-4">
                                  <Badge severity={s.severity} label={s.severity} />
                                </td>
                                <td className="py-3 px-4 text-cyan-400">{s.location || 'classes.dex'}</td>
                                <td className="py-3 px-4 text-amber-300 font-mono select-all">
                                  {s.masked_value}
                                </td>
                                <td className="py-3 px-4 text-right">
                                  <button
                                    onClick={() => handleCopy(s.masked_value, `sec_${idx}`)}
                                    className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
                                    title="Copy masked secret"
                                  >
                                    {copiedSecretId === `sec_${idx}` ? (
                                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                                    ) : (
                                      <Copy className="h-3.5 w-3.5" />
                                    )}
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </Card>
                  )}
                </div>
              )}

              {/* Tab 3: Network Intelligence */}
              {activeTab === 'network' && (
                <div className="space-y-4">
                  <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-start gap-3">
                    <Globe className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
                    <div>
                      <h4 className="text-sm font-semibold text-slate-100">Network Intelligence & Traffic Security</h4>
                      <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                        Static telemetry extracted from bytecode strings, resource XMLs, and network security configuration. Cleartext HTTP traffic is susceptible to active Man-in-the-Middle (MitM) eavesdropping.
                      </p>
                    </div>
                  </div>

                  {networkFindings.length === 0 ? (
                    <Card className="text-center py-10 text-slate-400 text-xs">
                      No network findings or cleartext communications detected.
                    </Card>
                  ) : (
                    <Card className="p-0 overflow-hidden border-slate-800">
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs font-mono">
                          <thead>
                            <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase text-[10px]">
                              <th className="py-3 px-4">Finding Type</th>
                              <th className="py-3 px-4">Severity</th>
                              <th className="py-3 px-4">Description</th>
                              <th className="py-3 px-4">Observed Telemetry</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/60">
                            {networkFindings.map((n, idx) => (
                              <tr key={n.id || idx} className="hover:bg-slate-900/30">
                                <td className="py-3 px-4 text-cyan-300 font-semibold">{n.type}</td>
                                <td className="py-3 px-4">
                                  <Badge severity={n.severity} label={n.severity} />
                                </td>
                                <td className="py-3 px-4 text-slate-300 font-sans max-w-xs">{n.description}</td>
                                <td className="py-3 px-4 text-slate-400 font-mono break-all select-all">
                                  {n.evidence || 'N/A'}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </Card>
                  )}
                </div>
              )}

              {/* Tab 4: Permissions */}
              {activeTab === 'permissions' && (
                <Card className="p-0 overflow-hidden border-slate-800">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead>
                        <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase text-[10px]">
                          <th className="py-3 px-4">Permission Name</th>
                          <th className="py-3 px-4">Risk Rating</th>
                          <th className="py-3 px-4">Description</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {permissions.map((p) => (
                          <tr key={p.id} className="hover:bg-slate-900/30">
                            <td className="py-3 px-4 text-cyan-300 font-medium break-all">{p.permission_name}</td>
                            <td className="py-3 px-4">
                              <Badge severity={p.danger_level} label={p.danger_level} />
                            </td>
                            <td className="py-3 px-4 text-slate-300 font-sans">{p.description || 'Standard system permission.'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>
              )}

              {/* Tab 5: Components */}
              {activeTab === 'components' && (
                <Card className="p-0 overflow-hidden border-slate-800">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead>
                        <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase text-[10px]">
                          <th className="py-3 px-4">Component Type</th>
                          <th className="py-3 px-4">Component Identifier</th>
                          <th className="py-3 px-4">Exported</th>
                          <th className="py-3 px-4">Permission Constraint</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {components.map((c) => (
                          <tr key={c.id} className="hover:bg-slate-900/30">
                            <td className="py-3 px-4 text-cyan-400 font-semibold uppercase">{c.component_type}</td>
                            <td className="py-3 px-4 text-slate-200 break-all">{c.component_name}</td>
                            <td className="py-3 px-4">
                              {c.exported ? (
                                <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30 font-bold">
                                  TRUE
                                </span>
                              ) : (
                                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                                  FALSE
                                </span>
                              )}
                            </td>
                            <td className="py-3 px-4 text-slate-400">{c.permission || 'None'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}
