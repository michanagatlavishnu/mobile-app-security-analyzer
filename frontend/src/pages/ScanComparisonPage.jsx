import React, { useState, useEffect } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  GitCompare,
  ArrowRight,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  History,
  Layers,
  ArrowLeft,
  ChevronRight,
  ArrowUpRight,
  ArrowDownRight,
  RefreshCw,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import scanService from '../services/scanService';
import { getRiskScoreColor, getSeverityColor, formatDate } from '../utils/formatters';

export default function ScanComparisonPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialBase = searchParams.get('baseScanId') || '';
  const initialTarget = searchParams.get('targetScanId') || '';

  const [scans, setScans] = useState([]);
  const [baseScanId, setBaseScanId] = useState(initialBase);
  const [targetScanId, setTargetScanId] = useState(initialTarget);
  const [comparison, setComparison] = useState(null);

  const [loadingScans, setLoadingScans] = useState(true);
  const [comparing, setComparing] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('new'); // 'new', 'resolved', 'persistent'

  // Fetch user's completed scans for dropdowns
  useEffect(() => {
    const loadScans = async () => {
      try {
        setLoadingScans(true);
        const data = await scanService.getScans();
        const completed = (data.scans || []).filter((s) => s.status === 'completed');
        setScans(completed);

        // Pre-select first two if not in query params
        if (!initialBase && completed.length >= 2) {
          setBaseScanId(String(completed[1].id));
          setTargetScanId(String(completed[0].id));
        }
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to load scan history for comparison.');
      } finally {
        setLoadingScans(false);
      }
    };
    loadScans();
  }, []);

  // Run comparison when base and target are selected
  const handleCompare = async () => {
    if (!baseScanId || !targetScanId) {
      setError('Please select both a base scan and a target scan to compare.');
      return;
    }
    if (baseScanId === targetScanId) {
      setError('Cannot compare a scan with itself. Please select two distinct scans.');
      return;
    }

    try {
      setComparing(true);
      setError('');
      setSearchParams({ baseScanId, targetScanId });
      const data = await scanService.compareScans(baseScanId, targetScanId);
      setComparison(data.comparison);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to generate scan comparison.');
    } finally {
      setComparing(false);
    }
  };

  useEffect(() => {
    if (baseScanId && targetScanId && baseScanId !== targetScanId && scans.length > 0) {
      handleCompare();
    }
  }, [baseScanId, targetScanId]);

  const diff = comparison?.diff;
  const base = comparison?.baseScan;
  const target = comparison?.targetScan;
  const changes = comparison?.changes;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
        <Link to="/scans" className="hover:text-cyan-400 flex items-center gap-1">
          <ArrowLeft className="h-3 w-3" /> Back to History
        </Link>
        <span>/</span>
        <span className="text-slate-200">Scan Comparison</span>
      </div>

      <PageHeader
        title="Audit Differential & Regression Analysis"
        description="Side-by-side comparison of security scores, threat vectors, and finding state transitions between two assessments."
        badge={<Badge label="DIFFERENTIAL ENGINE" variant="info" />}
      />

      {/* Selectors Card */}
      <Card title="Select Audits to Compare" subtitle="Choose a baseline audit and a target release audit">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 items-center">
          <div className="md:col-span-2">
            <label className="text-[11px] font-mono text-slate-400 block uppercase mb-1">
              Baseline Scan (Earlier Release)
            </label>
            <select
              value={baseScanId}
              onChange={(e) => setBaseScanId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
            >
              <option value="">-- Select Baseline Scan --</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  Scan #{s.id} - {s.packageName || s.apkName} ({s.versionName ? `v${s.versionName}` : ''} Score: {s.securityScore})
                </option>
              ))}
            </select>
          </div>

          <div className="flex justify-center text-cyan-400 pt-5">
            <GitCompare className="h-6 w-6" />
          </div>

          <div className="md:col-span-2">
            <label className="text-[11px] font-mono text-slate-400 block uppercase mb-1">
              Target Scan (Updated Release)
            </label>
            <select
              value={targetScanId}
              onChange={(e) => setTargetScanId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
            >
              <option value="">-- Select Target Scan --</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  Scan #{s.id} - {s.packageName || s.apkName} ({s.versionName ? `v${s.versionName}` : ''} Score: {s.securityScore})
                </option>
              ))}
            </select>
          </div>
        </div>
      </Card>

      {error && <ErrorState title="Comparison Error" message={error} />}

      {comparing && <LoadingSpinner message="Calculating vulnerability deltas and score difference..." />}

      {!comparing && comparison && (
        <>
          {/* Executive Delta Card */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="border-slate-800">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Security Score Delta</span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className={`text-3xl font-black font-mono ${diff.scoreDiff > 0 ? 'text-emerald-400' : diff.scoreDiff < 0 ? 'text-red-400' : 'text-slate-300'}`}>
                  {diff.scoreDiff > 0 ? `+${diff.scoreDiff}` : diff.scoreDiff}
                </span>
                <span className="text-xs text-slate-400 font-mono">pts</span>
              </div>
              <span className="text-[10px] text-slate-500 font-mono mt-1 block">
                {base.securityScore} &rarr; {target.securityScore}
              </span>
            </Card>

            <Card className="border-red-500/20 bg-red-950/10">
              <span className="text-[10px] font-mono text-red-400 uppercase tracking-wider block">New Findings</span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-black font-mono text-red-400">
                  +{diff.newFindingsCount}
                </span>
                <span className="text-xs text-red-400/80 font-mono">regressions</span>
              </div>
              <span className="text-[10px] text-red-400/70 font-mono mt-1 block">
                Introduced in target build
              </span>
            </Card>

            <Card className="border-emerald-500/20 bg-emerald-950/10">
              <span className="text-[10px] font-mono text-emerald-400 uppercase tracking-wider block">Resolved Findings</span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-black font-mono text-emerald-400">
                  -{diff.resolvedFindingsCount}
                </span>
                <span className="text-xs text-emerald-400/80 font-mono">remediated</span>
              </div>
              <span className="text-[10px] text-emerald-400/70 font-mono mt-1 block">
                Fixed since baseline build
              </span>
            </Card>

            <Card className="border-slate-800">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Persistent Findings</span>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-3xl font-black font-mono text-amber-300">
                  {diff.persistentFindingsCount}
                </span>
                <span className="text-xs text-slate-400 font-mono">active</span>
              </div>
              <span className="text-[10px] text-slate-500 font-mono mt-1 block">
                Remains open across builds
              </span>
            </Card>
          </div>

          {/* Version & Build Comparison Table */}
          <Card title="Build Context Comparison" subtitle="Package identifiers and artifact integrity verification">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                    <th className="py-2.5 px-3">Attribute</th>
                    <th className="py-2.5 px-3">Baseline (Scan #{base.id})</th>
                    <th className="py-2.5 px-3">Target (Scan #{target.id})</th>
                    <th className="py-2.5 px-3 text-right">Differential</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  <tr className="hover:bg-slate-900/30">
                    <td className="py-2.5 px-3 text-slate-400">Application Package</td>
                    <td className="py-2.5 px-3 text-slate-200">{base.packageName || base.apkName}</td>
                    <td className="py-2.5 px-3 text-slate-200">{target.packageName || target.apkName}</td>
                    <td className="py-2.5 px-3 text-right text-slate-400">
                      {base.packageName === target.packageName ? 'Identical Package' : 'Package Changed'}
                    </td>
                  </tr>
                  <tr className="hover:bg-slate-900/30">
                    <td className="py-2.5 px-3 text-slate-400">Version Name (Code)</td>
                    <td className="py-2.5 px-3 text-slate-200">{base.versionName || '1.0'} ({base.versionCode || 1})</td>
                    <td className="py-2.5 px-3 text-cyan-300 font-bold">{target.versionName || '1.0'} ({target.versionCode || 1})</td>
                    <td className="py-2.5 px-3 text-right text-cyan-400">
                      v{base.versionName || '1.0'} &rarr; v{target.versionName || '1.0'}
                    </td>
                  </tr>
                  <tr className="hover:bg-slate-900/30">
                    <td className="py-2.5 px-3 text-slate-400">Risk Level</td>
                    <td className="py-2.5 px-3">
                      <Badge severity={base.riskLevel} label={base.riskLevel} />
                    </td>
                    <td className="py-2.5 px-3">
                      <Badge severity={target.riskLevel} label={target.riskLevel} />
                    </td>
                    <td className="py-2.5 px-3 text-right font-bold">
                      {base.riskLevel === target.riskLevel ? 'Unchanged' : `${base.riskLevel} -> ${target.riskLevel}`}
                    </td>
                  </tr>
                  <tr className="hover:bg-slate-900/30">
                    <td className="py-2.5 px-3 text-slate-400">Vulnerabilities (Crit / High)</td>
                    <td className="py-2.5 px-3 text-slate-200">{base.criticalCount} Crit / {base.highCount} High</td>
                    <td className="py-2.5 px-3 text-slate-200">{target.criticalCount} Crit / {target.highCount} High</td>
                    <td className="py-2.5 px-3 text-right text-slate-300">
                      Diff: {target.totalFindings - base.totalFindings > 0 ? `+${target.totalFindings - base.totalFindings}` : target.totalFindings - base.totalFindings}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </Card>

          {/* Finding Change Matrix Tabs */}
          <div className="space-y-4">
            <div className="flex border-b border-slate-800 gap-4 text-sm font-medium">
              <button
                onClick={() => setActiveTab('new')}
                className={`pb-3 border-b-2 transition-colors flex items-center gap-2 ${
                  activeTab === 'new'
                    ? 'border-red-400 text-red-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <ShieldAlert className="h-4 w-4" />
                New Vulnerabilities ({changes.newFindings.length})
              </button>

              <button
                onClick={() => setActiveTab('resolved')}
                className={`pb-3 border-b-2 transition-colors flex items-center gap-2 ${
                  activeTab === 'resolved'
                    ? 'border-emerald-400 text-emerald-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <CheckCircle2 className="h-4 w-4" />
                Remediated Findings ({changes.resolvedFindings.length})
              </button>

              <button
                onClick={() => setActiveTab('persistent')}
                className={`pb-3 border-b-2 transition-colors flex items-center gap-2 ${
                  activeTab === 'persistent'
                    ? 'border-cyan-400 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Layers className="h-4 w-4" />
                Persistent ({changes.persistentFindings.length})
              </button>
            </div>

            {/* Tab 1: New Findings */}
            {activeTab === 'new' && (
              <div className="space-y-3">
                {changes.newFindings.length === 0 ? (
                  <Card className="text-center py-8 text-xs text-slate-400">
                    No new vulnerabilities detected in the target build.
                  </Card>
                ) : (
                  changes.newFindings.map((f, i) => (
                    <div key={i} className="p-3.5 rounded-xl bg-red-950/15 border border-red-500/30 flex items-start justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <Badge severity={f.severity} />
                          <h4 className="text-sm font-semibold text-slate-100">{f.title}</h4>
                        </div>
                        <p className="text-xs text-slate-300">{f.description}</p>
                        <div className="flex gap-2 text-[10px] font-mono text-slate-400 pt-1">
                          <span>{f.category}</span>
                          {f.cwe && <span>&bull; {f.cwe}</span>}
                          {f.location && <span>&bull; {f.location}</span>}
                        </div>
                      </div>
                      <Link to={`/scans/${target.id}/findings/${f.id}`} className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1 shrink-0 ml-3">
                        Inspect <ChevronRight className="h-3 w-3" />
                      </Link>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Tab 2: Remediated Findings */}
            {activeTab === 'resolved' && (
              <div className="space-y-3">
                {changes.resolvedFindings.length === 0 ? (
                  <Card className="text-center py-8 text-xs text-slate-400">
                    No vulnerabilities were remediated between these two builds.
                  </Card>
                ) : (
                  changes.resolvedFindings.map((f, i) => (
                    <div key={i} className="p-3.5 rounded-xl bg-emerald-950/15 border border-emerald-500/30 flex items-start justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-[10px] font-bold font-mono">
                            REMEDIATED
                          </span>
                          <h4 className="text-sm font-semibold text-slate-200 line-through opacity-80">{f.title}</h4>
                        </div>
                        <p className="text-xs text-slate-400">{f.description}</p>
                        <div className="flex gap-2 text-[10px] font-mono text-slate-500 pt-1">
                          <span>Was: {f.severity}</span>
                          <span>&bull; {f.category}</span>
                          {f.location && <span>&bull; {f.location}</span>}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {/* Tab 3: Persistent Findings */}
            {activeTab === 'persistent' && (
              <div className="space-y-3">
                {changes.persistentFindings.length === 0 ? (
                  <Card className="text-center py-8 text-xs text-slate-400">
                    No persistent findings shared between these builds.
                  </Card>
                ) : (
                  changes.persistentFindings.map((p, i) => (
                    <div key={i} className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex items-start justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <Badge severity={p.target.severity} />
                          <h4 className="text-sm font-semibold text-slate-100">{p.target.title}</h4>
                          <span className="text-[10px] font-mono text-amber-300/80 bg-amber-950/20 px-1.5 py-0.5 rounded border border-amber-500/20">
                            STILL PRESENT
                          </span>
                        </div>
                        <p className="text-xs text-slate-300">{p.target.description}</p>
                        <div className="flex gap-2 text-[10px] font-mono text-slate-400 pt-1">
                          <span>{p.target.category}</span>
                          {p.target.cwe && <span>&bull; {p.target.cwe}</span>}
                          {p.target.location && <span>&bull; {p.target.location}</span>}
                        </div>
                      </div>
                      <Link to={`/scans/${target.id}/findings/${p.target.id}`} className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1 shrink-0 ml-3">
                        Inspect <ChevronRight className="h-3 w-3" />
                      </Link>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
