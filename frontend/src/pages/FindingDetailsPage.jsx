import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ArrowLeft,
  Copy,
  Check,
  Save,
  Clock,
  User,
  Info,
  ExternalLink,
  CheckCircle2,
  FileCode,
  Tag,
  AlertTriangle,
} from 'lucide-react';
import PageHeader from '../components/PageHeader';
import Card from '../components/Card';
import Button from '../components/Button';
import Badge from '../components/Badge';
import LoadingSpinner from '../components/LoadingSpinner';
import ErrorState from '../components/ErrorState';
import scanService from '../services/scanService';
import vulnerabilityService from '../services/vulnerabilityService';
import { formatDate, getSeverityColor } from '../utils/formatters';

export default function FindingDetailsPage() {
  const { id: scanId, findingId } = useParams();
  const navigate = useNavigate();

  const [finding, setFinding] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  // Editable remediation fields
  const [status, setStatus] = useState('OPEN');
  const [analystNote, setAnalystNote] = useState('');
  const [copiedEvidence, setCopiedEvidence] = useState(false);

  const fetchFinding = async () => {
    try {
      setLoading(true);
      setError('');
      const [findingData, historyData] = await Promise.all([
        scanService.getFinding(scanId, findingId),
        vulnerabilityService.getHistory(findingId).catch(() => ({ data: [] }))
      ]);
      setFinding(findingData.finding);
      setStatus(findingData.finding.status || 'OPEN');
      setAnalystNote(findingData.finding.analyst_note || '');
      setHistory(historyData.data || []);
    } catch (err) {
      setError(err.response?.data?.message || `Failed to load finding #${findingId}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFinding();
  }, [scanId, findingId]);

  const handleSaveRemediation = async (e) => {
    e.preventDefault();
    try {
      setSaving(true);
      setError('');
      setSuccessMessage('');
      const res = await scanService.updateFinding(scanId, findingId, {
        status,
        analystNote,
      });
      setFinding(res.finding);
      try {
        const hist = await vulnerabilityService.getHistory(findingId);
        setHistory(hist.data || []);
      } catch {}
      setSuccessMessage('Remediation tracking and analyst note successfully updated.');
      setTimeout(() => setSuccessMessage(''), 4000);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update finding status.');
    } finally {
      setSaving(false);
    }
  };

  const handleCopyEvidence = () => {
    if (!finding?.evidence) return;
    navigator.clipboard.writeText(finding.evidence);
    setCopiedEvidence(true);
    setTimeout(() => setCopiedEvidence(false), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
        <Link to={`/scans/${scanId}`} className="hover:text-cyan-400 flex items-center gap-1">
          <ArrowLeft className="h-3 w-3" /> Back to Scan #{scanId}
        </Link>
        <span>/</span>
        <span className="text-slate-200">Finding #{findingId}</span>
      </div>

      {loading && <LoadingSpinner message={`Loading finding #${findingId} telemetry...`} />}

      {error && <ErrorState title="Error Loading Finding" message={error} onRetry={fetchFinding} />}

      {!loading && finding && (
        <>
          <PageHeader
            title={finding.title}
            description="Deep static analysis vulnerability telemetry, risk impact, and remediation lifecycle tracking."
            badge={<Badge severity={finding.severity} label={`SEVERITY: ${finding.severity}`} size="md" />}
            actions={
              <Link to={`/scans/${scanId}`}>
                <Button variant="outline" size="sm">
                  <ArrowLeft className="h-3.5 w-3.5 mr-1.5" />
                  View All Findings
                </Button>
              </Link>
            }
          />

          {successMessage && (
            <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2 font-mono">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>{successMessage}</span>
            </div>
          )}

          {/* Classification & Metadata Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card className="border-slate-800">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Classification</span>
              <span className="text-sm font-semibold text-slate-200 mt-1 block">{finding.category}</span>
            </Card>

            <Card className="border-slate-800">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Detection Confidence</span>
              <span className="text-sm font-semibold text-cyan-400 mt-1 block uppercase font-mono">
                {finding.confidence || 'HIGH'}
              </span>
            </Card>

            <Card className="border-slate-800">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Analyzer Module</span>
              <span className="text-sm font-semibold text-slate-200 mt-1 block font-mono">
                {finding.analyzer || 'static_analyzer'}
              </span>
            </Card>

            <Card className="border-slate-800">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Lifecycle Status</span>
              <span className="text-sm font-semibold text-amber-300 mt-1 block font-mono">
                {finding.status}
              </span>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Details & Evidence */}
            <div className="lg:col-span-2 space-y-6">
              {/* Finding Description */}
              <Card title="Vulnerability Overview" subtitle="Technical description and standards mapping">
                <p className="text-sm text-slate-300 leading-relaxed">{finding.description}</p>

                <div className="flex flex-wrap gap-2.5 mt-4 pt-4 border-t border-slate-800 text-xs">
                  {finding.cwe && (
                    <div className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-cyan-300 font-mono flex items-center gap-1.5">
                      <Tag className="h-3 w-3" />
                      <span>{finding.cwe}</span>
                    </div>
                  )}
                  {finding.owasp_category && (
                    <div className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-amber-300 font-mono flex items-center gap-1.5">
                      <ShieldAlert className="h-3 w-3" />
                      <span>{finding.owasp_category}</span>
                    </div>
                  )}
                  {finding.location && (
                    <div className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-400 font-mono flex items-center gap-1.5">
                      <FileCode className="h-3 w-3" />
                      <span>{finding.location}</span>
                    </div>
                  )}
                </div>
              </Card>

              {/* Observed Evidence */}
              {finding.evidence && (
                <Card
                  title="Observed Static Evidence"
                  subtitle="Extracted signature match (strictly masked for credentials)"
                  actions={
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={handleCopyEvidence}
                      className="text-xs text-slate-400 hover:text-slate-200"
                    >
                      {copiedEvidence ? (
                        <>
                          <Check className="h-3.5 w-3.5 mr-1 text-emerald-400" />
                          Copied
                        </>
                      ) : (
                        <>
                          <Copy className="h-3.5 w-3.5 mr-1" />
                          Copy Evidence
                        </>
                      )}
                    </Button>
                  }
                >
                  <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 break-all select-all leading-relaxed">
                    {finding.evidence}
                  </div>
                </Card>
              )}

              {/* Security Impact */}
              {finding.impact && (
                <Card title="Security Impact Assessment" className="border-red-500/20 bg-red-950/10">
                  <div className="flex items-start gap-3">
                    <AlertTriangle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
                    <p className="text-xs text-slate-300 leading-relaxed">{finding.impact}</p>
                  </div>
                </Card>
              )}

              {/* Remediation Guidance */}
              {finding.recommendation && (
                <Card title="Remediation Guidance" className="border-cyan-500/20 bg-cyan-950/10">
                  <p className="text-xs text-slate-300 leading-relaxed">{finding.recommendation}</p>
                </Card>
              )}
            </div>

            {/* Right 1 Col: Remediation Tracking Form */}
            <div className="space-y-6">
              <Card title="Remediation Lifecycle" subtitle="Track resolution state and record analyst notes">
                <form onSubmit={handleSaveRemediation} className="space-y-4 text-xs">
                  <div>
                    <label className="font-semibold text-slate-300 block mb-1.5 font-mono text-[11px] uppercase">
                      Triage Status
                    </label>
                    <select
                      value={status}
                      onChange={(e) => setStatus(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                    >
                      <option value="OPEN">OPEN (Unaddressed)</option>
                      <option value="ACKNOWLEDGED">ACKNOWLEDGED (Triaged)</option>
                      <option value="IN_PROGRESS">IN_PROGRESS (Remediating)</option>
                      <option value="RESOLVED">RESOLVED (Fixed)</option>
                      <option value="FALSE_POSITIVE">FALSE_POSITIVE (Verified Exception)</option>
                    </select>
                  </div>

                  <div>
                    <label className="font-semibold text-slate-300 block mb-1.5 font-mono text-[11px] uppercase">
                      Analyst Note / Context
                    </label>
                    <textarea
                      rows={5}
                      value={analystNote}
                      onChange={(e) => setAnalystNote(e.target.value)}
                      placeholder="Add assessment verification notes, owner sign-off, or mitigation tickets..."
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-slate-200 placeholder-slate-500 font-sans leading-relaxed focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  {finding.resolved_at && (
                    <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-[11px] text-slate-400 font-mono flex items-center gap-1.5">
                      <Clock className="h-3.5 w-3.5 text-cyan-400" />
                      <span>Resolved At: {formatDate(finding.resolved_at)}</span>
                    </div>
                  )}

                  <Button
                    type="submit"
                    variant="primary"
                    size="md"
                    loading={saving}
                    className="w-full justify-center shadow-cyber-glow"
                  >
                    <Save className="h-4 w-4 mr-1.5" />
                    Save Remediation Note
                  </Button>
                </form>
              </Card>

              {/* Finding History / SecOps Audit Trail */}
              <Card title="SecOps Audit Trail" subtitle="Chronological history of status updates and notes">
                <div className="space-y-3">
                  {history.map((h, idx) => (
                    <div key={h.id || idx} className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs space-y-1">
                      <div className="flex items-center justify-between text-[11px] font-mono">
                        <span className="text-slate-400 font-semibold">{h.user_name || 'System Operator'}</span>
                        <span className="text-slate-500">{formatDate(h.created_at)}</span>
                      </div>
                      <div className="flex items-center gap-1.5 font-mono text-[10px]">
                        <span className="text-slate-400">{h.previous_status || 'INITIAL'}</span>
                        <span className="text-slate-600">→</span>
                        <Badge label={h.new_status} variant={h.new_status === 'RESOLVED' ? 'success' : h.new_status === 'FALSE_POSITIVE' ? 'default' : 'warning'} size="xs" />
                      </div>
                      {h.note && (
                        <p className="text-slate-300 text-xs italic bg-slate-900/60 p-2 rounded border border-slate-800/80 mt-1">
                          "{h.note}"
                        </p>
                      )}
                    </div>
                  ))}
                  {history.length === 0 && (
                    <p className="text-xs text-slate-500 italic py-2 text-center">No previous history entries recorded.</p>
                  )}
                </div>
              </Card>

              {/* Target Artifact Info Card */}
              <Card title="Target Application Context" subtitle="Associated scan archive metadata">
                <div className="space-y-2.5 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Package</span>
                    <span className="text-slate-200 break-all">{finding.package_name || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Version</span>
                    <span className="text-slate-200">{finding.version_name || '1.0'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Source Archive</span>
                    <span className="text-slate-300">{finding.original_filename}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block uppercase text-[10px]">Scan ID</span>
                    <span className="text-cyan-400">#{scanId}</span>
                  </div>
                </div>
              </Card>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
