import React, { useState, useEffect } from 'react';
import {
  Server,
  Database,
  Cpu,
  RefreshCw,
  HardDrive,
  Activity,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Terminal,
  Container,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import adminService from '../services/adminService';

export default function AdminSystemHealthPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchHealth = async () => {
    try {
      setLoading(true);
      setError('');
      const res = await adminService.getSystemHealth();
      setData(res.health);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to poll system runtime health.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  const formatUptime = (seconds) => {
    if (!seconds) return '0s';
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${d > 0 ? `${d}d ` : ''}${h > 0 ? `${h}h ` : ''}${m}m ${s}s`;
  };

  const mem = data?.memory || {};
  const tel = data?.telemetry || {};

  return (
    <div className="space-y-6">
      <PageHeader
        title="System Runtime & Infrastructure Health"
        description="Real-time daemon operability, database connection latency, analyzer subsystem status, and hardware resource telemetry."
        badge={
          <Badge
            label={data?.apiStatus === 'online' ? 'SERVICES OPERATIONAL' : 'DEGRADED'}
            variant={data?.apiStatus === 'online' ? 'success' : 'danger'}
          />
        }
        actions={
          <Button variant="outline" size="sm" onClick={fetchHealth} disabled={loading}>
            <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${loading ? 'animate-spin' : ''}`} /> Refresh Telemetry
          </Button>
        }
      />

      {loading && <LoadingSpinner message="Polling daemon subsystems and database latency..." />}
      {error && <ErrorState title="System Health Error" message={error} onRetry={fetchHealth} />}

      {!loading && !error && data && (
        <>
          {/* Subsystem Health Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* API Server */}
            <Card className="border-slate-800 p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono uppercase text-slate-400">REST API Subsystem</span>
                <Server className="h-4 w-4 text-cyan-400" />
              </div>
              <div className="flex items-center gap-2 mt-2">
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
                <span className="text-lg font-bold font-mono text-emerald-400 uppercase">{data.apiStatus}</span>
              </div>
              <p className="text-[11px] text-slate-500 font-mono mt-1">Uptime: {formatUptime(data.uptimeSeconds)}</p>
            </Card>

            {/* Database */}
            <Card className="border-slate-800 p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono uppercase text-slate-400">MySQL Database</span>
                <Database className="h-4 w-4 text-sky-400" />
              </div>
              <div className="flex items-center gap-2 mt-2">
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
                <span className="text-lg font-bold font-mono text-emerald-400 uppercase">{data.databaseStatus}</span>
              </div>
              <p className="text-[11px] text-slate-500 font-mono mt-1">Ping Latency: {data.databaseLatencyMs} ms</p>
            </Card>

            {/* Python Analyzer Subsystem */}
            <Card className="border-slate-800 p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono uppercase text-slate-400">Python SAST Engine</span>
                <Cpu className="h-4 w-4 text-amber-400" />
              </div>
              <div className="flex items-center gap-2 mt-2">
                <span className={`h-2.5 w-2.5 rounded-full ${data.analyzerStatus === 'ready' ? 'bg-emerald-400' : 'bg-red-400'}`}></span>
                <span className={`text-lg font-bold font-mono uppercase ${data.analyzerStatus === 'ready' ? 'text-emerald-400' : 'text-red-400'}`}>
                  {data.analyzerStatus}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-mono mt-1 truncate" title={data.pythonVersion}>
                {data.pythonVersion}
              </p>
            </Card>

            {/* Docker Host Verification */}
            <Card className="border-slate-800 p-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono uppercase text-slate-400">Docker Runtime</span>
                <Container className="h-4 w-4 text-slate-400" />
              </div>
              <div className="flex items-center gap-2 mt-2">
                <span className="h-2.5 w-2.5 rounded-full bg-slate-500"></span>
                <span className="text-sm font-bold font-mono text-slate-300">Local Daemon</span>
              </div>
              <p className="text-[11px] text-slate-500 font-mono mt-1">Docker runtime status: Not verified on this host</p>
            </Card>
          </div>

          {/* Runtime Environment & Platform Statistics */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Runtime Parameters */}
            <Card title="Runtime Environment" subtitle="Engine build configuration and process versions">
              <div className="space-y-2.5 text-xs font-mono mt-1">
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500">Application Version:</span>
                  <span className="text-cyan-400 font-bold">v{data.appVersion}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500">Node.js Runtime:</span>
                  <span className="text-slate-200">{data.nodeVersion}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500">Python Interpreter:</span>
                  <span className="text-slate-200">{data.pythonVersion}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500">Deployment Environment:</span>
                  <span className="text-emerald-400 font-bold uppercase">{data.environment}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800">
                  <span className="text-slate-500">Process Memory (RSS):</span>
                  <span className="text-slate-200">{mem.rssMb ?? 0} MB</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-500">V8 Heap Allocation:</span>
                  <span className="text-slate-200">{mem.heapUsedMb ?? 0} MB / {mem.heapTotalMb ?? 0} MB</span>
                </div>
              </div>
            </Card>

            {/* Execution Telemetry */}
            <Card title="Execution Performance Telemetry" subtitle="Static analysis duration and failure rates">
              <div className="grid grid-cols-2 gap-3 text-center font-mono mt-1">
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
                  <p className="text-[10px] uppercase text-slate-500">Total Scans</p>
                  <p className="text-2xl font-bold text-cyan-400 mt-1">{tel.totalScans ?? 0}</p>
                </div>
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
                  <p className="text-[10px] uppercase text-slate-500">Completed Scans</p>
                  <p className="text-2xl font-bold text-emerald-400 mt-1">{tel.completedScans ?? 0}</p>
                </div>
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
                  <p className="text-[10px] uppercase text-slate-500">Failed Scans</p>
                  <p className="text-2xl font-bold text-red-400 mt-1">{tel.failedScans ?? 0}</p>
                </div>
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
                  <p className="text-[10px] uppercase text-slate-500">Avg Scan Duration</p>
                  <p className="text-2xl font-bold text-amber-400 mt-1">
                    {tel.avgScanDurationSeconds !== null ? `${tel.avgScanDurationSeconds}s` : '—'}
                  </p>
                </div>
                <div className="col-span-2 p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between px-6">
                  <div>
                    <span className="text-[10px] uppercase text-slate-500 block">Total APK Storage</span>
                    <span className="text-xl font-bold text-slate-200 mt-0.5 block">{tel.storageMb ?? 0} MB</span>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] uppercase text-slate-500 block">Archived Builds</span>
                    <span className="text-xl font-bold text-slate-200 mt-0.5 block">{tel.totalApkFiles ?? 0} files</span>
                  </div>
                </div>
              </div>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
