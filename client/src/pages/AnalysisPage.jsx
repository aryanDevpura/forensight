import React, { useState, useEffect, useCallback } from 'react';
import { Card } from '../components/common/Card';
import { StatusBadge } from '../components/common/StatusBadge';
import { fetchEvidence, triggerAnalysis, fetchFindings } from '../api/client';
import {
  Activity,
  Play,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  FileCode,
  Network,
  Cpu,
  ShieldAlert,
  Server,
  Layers,
  ArrowRight,
} from 'lucide-react';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function AnalysisPage() {
  const [evidenceList, setEvidenceList] = useState([]);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [findings, setFindings] = useState([]);
  const [isLoadingEvidence, setIsLoadingEvidence] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isLoadingFindings, setIsLoadingFindings] = useState(false);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  // Load available evidence list
  const loadEvidence = useCallback(async () => {
    setIsLoadingEvidence(true);
    setError(null);
    try {
      const records = await fetchEvidence();
      // Filter for PCAP / packet capture evidence types
      const pcapRecords = records.filter((item) =>
        ['PCAP', 'PCAPNG'].includes((item.evidence_type || '').toUpperCase())
      );
      setEvidenceList(pcapRecords);

      // Auto-select first item if none selected
      if (pcapRecords.length > 0 && !selectedEvidenceId) {
        setSelectedEvidenceId(pcapRecords[0].evidence_id);
      }
    } catch (err) {
      setError(err.message || 'Failed to load evidence items');
    } finally {
      setIsLoadingEvidence(false);
    }
  }, [selectedEvidenceId]);

  useEffect(() => {
    loadEvidence();
  }, [loadEvidence]);

  // When selectedEvidenceId changes, load any existing findings
  const loadFindingsForSelected = useCallback(async (evId) => {
    if (!evId) return;
    setIsLoadingFindings(true);
    setError(null);
    try {
      const items = await fetchFindings(evId);
      setFindings(items);
    } catch (err) {
      // If none found or error, handle gracefully
      setFindings([]);
    } finally {
      setIsLoadingFindings(false);
    }
  }, []);

  useEffect(() => {
    if (selectedEvidenceId) {
      // Reset past run result view so we don't display mismatched metrics
      setAnalysisResult(null);
      setSuccessMessage(null);
      loadFindingsForSelected(selectedEvidenceId);
    }
  }, [selectedEvidenceId, loadFindingsForSelected]);

  // Run forensic analysis
  const handleRunAnalysis = async () => {
    if (!selectedEvidenceId) {
      setError('Please select an evidence item to analyze.');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setSuccessMessage(null);

    try {
      const res = await triggerAnalysis(selectedEvidenceId);
      setAnalysisResult(res);
      setFindings(res.findings || []);
      setSuccessMessage(
        `Forensic inspection completed for ${selectedEvidenceId}. Generated ${res.findings_count} finding(s).`
      );

      // Refresh evidence list in background to reflect ANALYZED status badge
      fetchEvidence().then((updated) => {
        const pcapRecords = updated.filter((item) =>
          ['PCAP', 'PCAPNG'].includes((item.evidence_type || '').toUpperCase())
        );
        setEvidenceList(pcapRecords);
      }).catch(() => {});
    } catch (err) {
      setError(err.message || 'Analysis failed to execute');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const selectedEvidence = evidenceList.find((e) => e.evidence_id === selectedEvidenceId);

  return (
    <div className="space-y-5">
      {/* Top Banner / Alerts */}
      {error && (
        <div className="p-3 bg-[#fee2e2] border border-[#ef4444]/40 text-[#991b1b] rounded-sm text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-[#991b1b]" />
            <span className="font-mono">{error}</span>
          </div>
          <button
            onClick={() => setError(null)}
            className="text-[#991b1b] hover:text-[#7f1d1d] font-bold text-sm ml-2"
          >
            &times;
          </button>
        </div>
      )}

      {successMessage && (
        <div className="p-3 bg-[#f0f9f3] border border-[#227244]/40 text-[#144629] rounded-sm text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-[#1a5935]" />
            <span className="font-mono">{successMessage}</span>
          </div>
          <button
            onClick={() => setSuccessMessage(null)}
            className="text-[#144629] hover:text-[#0d2f1b] font-bold text-sm ml-2"
          >
            &times;
          </button>
        </div>
      )}

      {/* Target Evidence Selection & Execution Console */}
      <Card
        title="Forensic Evidence Inspection Target"
        subtitle="Select an acquired PCAP network capture artifact and trigger deep packet inspection"
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                loadEvidence();
                if (selectedEvidenceId) loadFindingsForSelected(selectedEvidenceId);
              }}
              disabled={isLoadingEvidence || isAnalyzing}
              className="p-1.5 text-[#536050] hover:text-[#111813] hover:bg-[#eaede8] rounded-sm border border-[#d7ded4] transition-colors disabled:opacity-50"
              title="Refresh evidence list"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingEvidence ? 'animate-spin' : ''}`} />
            </button>
            <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
              Engine: Pure-Python PCAP Parser
            </div>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-[#111813] mb-1 uppercase tracking-wider">
                Select PCAP Evidence Item
              </label>
              {isLoadingEvidence ? (
                <div className="h-9 flex items-center px-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050]">
                  Loading registered evidence...
                </div>
              ) : evidenceList.length === 0 ? (
                <div className="h-9 flex items-center px-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050]">
                  No PCAP evidence registered yet. Upload .pcap files in the Evidence Repository.
                </div>
              ) : (
                <select
                  value={selectedEvidenceId}
                  onChange={(e) => setSelectedEvidenceId(e.target.value)}
                  disabled={isAnalyzing}
                  className="w-full h-9 px-3 text-xs bg-white border border-[#bdc7ba] rounded-sm focus:outline-none focus:border-[#1a5935] text-[#111813] font-mono"
                >
                  {evidenceList.map((ev) => (
                    <option key={ev.evidence_id} value={ev.evidence_id}>
                      {ev.evidence_id} — {ev.file_name} ({formatBytes(ev.file_size_bytes)}) [{ev.status}]
                    </option>
                  ))}
                </select>
              )}
            </div>

            <div>
              <button
                onClick={handleRunAnalysis}
                disabled={!selectedEvidenceId || isAnalyzing || isLoadingEvidence}
                className="w-full h-9 flex items-center justify-center gap-2 bg-[#1a5935] hover:bg-[#144629] text-white px-4 rounded-sm text-xs font-semibold tracking-wide transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-none"
              >
                {isAnalyzing ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Analyzing Packets...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Run Forensic Analysis</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Selected Evidence Metadata Card */}
          {selectedEvidence && (
            <div className="bg-[#faf8f3] border border-[#d7ded4] p-3 rounded-sm text-xs grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div>
                <span className="text-[#6c7a68] uppercase text-[10px] font-bold block">Status</span>
                <div className="mt-0.5">
                  <StatusBadge status={selectedEvidence.status} />
                </div>
              </div>
              <div>
                <span className="text-[#6c7a68] uppercase text-[10px] font-bold block">File Size</span>
                <span className="font-mono text-[#111813] font-medium mt-0.5 block">
                  {formatBytes(selectedEvidence.file_size_bytes)}
                </span>
              </div>
              <div>
                <span className="text-[#6c7a68] uppercase text-[10px] font-bold block">Source Device</span>
                <span className="font-mono text-[#111813] truncate mt-0.5 block">
                  {selectedEvidence.source_device}
                </span>
              </div>
              <div>
                <span className="text-[#6c7a68] uppercase text-[10px] font-bold block">SHA-256 Digest</span>
                <span
                  className="font-mono text-[11px] text-[#3e483c] truncate mt-0.5 block"
                  title={selectedEvidence.sha256_hash}
                >
                  {selectedEvidence.sha256_hash ? `${selectedEvidence.sha256_hash.substring(0, 16)}...` : 'N/A'}
                </span>
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Network & Packet Metrics Overview (when analysis has run or was returned) */}
      {analysisResult && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white border border-[#d7ded4] p-3.5 rounded-sm">
            <div className="flex items-center justify-between text-[#6c7a68] mb-1">
              <span className="text-[11px] uppercase tracking-wider font-semibold">Total Packets</span>
              <Layers className="w-4 h-4 text-[#1a5935]" />
            </div>
            <div className="text-xl font-bold font-mono text-[#111813]">
              {analysisResult.packet_count.toLocaleString()}
            </div>
            <span className="text-[11px] text-[#6c7a68]">
              {formatBytes(analysisResult.total_bytes)} parsed
            </span>
          </div>

          <div className="bg-white border border-[#d7ded4] p-3.5 rounded-sm">
            <div className="flex items-center justify-between text-[#6c7a68] mb-1">
              <span className="text-[11px] uppercase tracking-wider font-semibold">Protocols</span>
              <Network className="w-4 h-4 text-[#1a5935]" />
            </div>
            <div className="text-xl font-bold font-mono text-[#111813]">
              {Object.keys(analysisResult.protocols || {}).length}
            </div>
            <span className="text-[11px] text-[#6c7a68] truncate block" title={Object.keys(analysisResult.protocols || {}).join(', ')}>
              {Object.keys(analysisResult.protocols || {}).join(', ') || 'None identified'}
            </span>
          </div>

          <div className="bg-white border border-[#d7ded4] p-3.5 rounded-sm">
            <div className="flex items-center justify-between text-[#6c7a68] mb-1">
              <span className="text-[11px] uppercase tracking-wider font-semibold">Active Endpoints</span>
              <Server className="w-4 h-4 text-[#1a5935]" />
            </div>
            <div className="text-xl font-bold font-mono text-[#111813]">
              {Object.keys(analysisResult.source_ips || {}).length} / {Object.keys(analysisResult.destination_ips || {}).length}
            </div>
            <span className="text-[11px] text-[#6c7a68]">Src IPs / Dst IPs</span>
          </div>

          <div className="bg-white border border-[#d7ded4] p-3.5 rounded-sm">
            <div className="flex items-center justify-between text-[#6c7a68] mb-1">
              <span className="text-[11px] uppercase tracking-wider font-semibold">Findings Generated</span>
              <ShieldAlert className="w-4 h-4 text-[#b45309]" />
            </div>
            <div className="text-xl font-bold font-mono text-[#111813]">
              {analysisResult.findings_count}
            </div>
            <span className="text-[11px] text-[#6c7a68]">Alerts & anomalies</span>
          </div>
        </div>
      )}

      {/* Forensic Findings Table */}
      <Card
        title="Forensic Findings & Alert Registry"
        subtitle={
          selectedEvidenceId
            ? `Structured forensic findings associated with ${selectedEvidenceId}`
            : 'Structured forensic findings from packet captures and system artifacts'
        }
        action={
          <div className="text-xs font-mono text-[#536050] bg-[#faf8f3] px-2.5 py-1 border border-[#d7ded4] rounded-sm">
            Total Findings: <span className="font-bold text-[#111813]">{findings.length}</span>
          </div>
        }
      >
        <div className="border border-[#d7ded4] rounded-sm overflow-hidden bg-white">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
              <tr>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Finding ID</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Evidence Ref</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Category</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Severity</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Title & Details</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Detected At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#eaede8] bg-white">
              {isLoadingFindings ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[#536050]">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-[#1a5935]" />
                      <span>Loading forensic findings...</span>
                    </div>
                  </td>
                </tr>
              ) : findings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[#536050]">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <Activity className="w-7 h-7 text-[#94a190]" />
                      <p className="text-sm font-semibold text-[#111813]">No Forensic Findings</p>
                      <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                        {selectedEvidence
                          ? selectedEvidence.status === 'ANALYZED'
                            ? 'Analysis concluded with no anomalous threats detected in this capture.'
                            : 'This evidence has not been analyzed yet. Click "Run Forensic Analysis" above to inspect packet streams.'
                          : 'Select an evidence artifact above and run analysis to inspect packets and generate findings.'}
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                findings.map((f) => {
                  let parsedDetails = null;
                  try {
                    if (f.details && typeof f.details === 'string') {
                      parsedDetails = JSON.parse(f.details);
                    }
                  } catch (e) {
                    parsedDetails = null;
                  }

                  return (
                    <tr key={f.finding_id} className="hover:bg-[#faf8f3] transition-colors">
                      <td className="py-2.5 px-3 font-mono font-bold text-[#111813] whitespace-nowrap">
                        {f.finding_id}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[#536050] whitespace-nowrap">
                        {f.evidence_id}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className="font-mono text-[11px] px-1.5 py-0.5 bg-[#eaede8] text-[#2c332b] rounded-sm border border-[#d7ded4]">
                          {f.category}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <StatusBadge
                          status={f.severity}
                          label={f.severity}
                          size="xs"
                        />
                      </td>
                      <td className="py-2.5 px-3 max-w-md">
                        <div className="font-medium text-[#111813]">{f.title}</div>
                        {parsedDetails ? (
                          <div className="text-[11px] font-mono text-[#536050] mt-1 bg-[#faf8f3] p-1.5 rounded-sm border border-[#eaede8] overflow-x-auto max-h-24">
                            {JSON.stringify(parsedDetails, null, 2)}
                          </div>
                        ) : f.details ? (
                          <p className="text-[11px] text-[#536050] mt-0.5 line-clamp-2">
                            {f.details}
                          </p>
                        ) : null}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-[#536050] whitespace-nowrap">
                        {f.detected_at
                          ? new Date(f.detected_at).toLocaleString()
                          : 'N/A'}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Forensic Engine Modules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 text-xs">
        <Card title="PCAP Stream Extraction">
          <p className="text-[#536050] leading-relaxed">
            Deterministic packet header parser reads ethernet, IPv4/IPv6, TCP, and UDP structures. Calculates packet frequencies, payload volumes, and conversation pairs without third-party binary hooks.
          </p>
        </Card>
        <Card title="Heuristic Anomaly Checks">
          <p className="text-[#536050] leading-relaxed">
            Detects horizontal and vertical port scanning behavior by tracking destination port dispersion per source IP. Flags unencrypted protocol usage (HTTP, FTP, Telnet).
          </p>
        </Card>
        <Card title="Cryptographic Assurance">
          <p className="text-[#536050] leading-relaxed">
            Analysis runs in non-destructive read-only mode. The original evidence artifact and its acquisition SHA-256 hash are strictly preserved and logged to the chain-of-custody.
          </p>
        </Card>
      </div>
    </div>
  );
}
