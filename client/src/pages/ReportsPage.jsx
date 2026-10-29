import React, { useState, useEffect, useCallback } from 'react';
import { Card } from '../components/common/Card';
import { StatusBadge } from '../components/common/StatusBadge';
import {
  fetchReports,
  fetchReport,
  generateReport,
  downloadReport,
  fetchEvidence,
} from '../api/client';
import {
  FileText,
  Download,
  Eye,
  RefreshCw,
  AlertTriangle,
  Lock,
  Clock,
  X,
  Shield,
  Layers,
} from 'lucide-react';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function ReportsPage() {
  const [reportsList, setReportsList] = useState([]);
  const [evidenceList, setEvidenceList] = useState([]);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState('');
  const [reportTitle, setReportTitle] = useState('');
  const [examinerName, setExaminerName] = useState('Forensic Examiner');
  const [examinerNotes, setExaminerNotes] = useState('');

  const [isLoading, setIsLoading] = useState(true);
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState(null);
  const [downloadingId, setDownloadingId] = useState(null);
  const [downloadError, setDownloadError] = useState(null);

  // Active preview state
  const [activePreview, setActivePreview] = useState(null);
  const [isLoadingPreview, setIsLoadingPreview] = useState(false);

  // Load evidence and historical reports
  const loadData = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    // 1. Fetch registered evidence records directly (matching EvidencePage behavior)
    try {
      const records = await fetchEvidence();
      const list = Array.isArray(records) ? records : [];
      setEvidenceList(list);
      setSelectedEvidenceId((prev) => prev || (list.length > 0 ? list[0].evidence_id : ''));
    } catch (err) {
      setError(err.message || 'Failed to load evidence records');
    }

    // 2. Fetch report history independently (non-blocking: missing/empty reports won't clear evidence)
    try {
      const reports = await fetchReports();
      setReportsList(Array.isArray(reports) ? reports : []);
    } catch {
      setReportsList([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const selectedEvidence = evidenceList.find((e) => e.evidence_id === selectedEvidenceId);

  // Generate evidence report
  const handleGenerate = async (e) => {
    e.preventDefault();
    if (!selectedEvidenceId) {
      setError('Please select an evidence artifact to generate a report.');
      return;
    }

    setIsGenerating(true);
    setError(null);
    try {
      const payload = {
        evidence_id: selectedEvidenceId,
        title: reportTitle.trim() || null,
        examiner_name: examinerName.trim() || 'Forensic Examiner',
        notes: examinerNotes.trim() || null,
      };

      const newReport = await generateReport(payload);
      setActivePreview(newReport);

      // Refresh report list
      const updatedReports = await fetchReports();
      setReportsList(updatedReports);
    } catch (err) {
      setError(err.message || 'Report generation failed');
    } finally {
      setIsGenerating(false);
    }
  };

  // Preview an existing report
  const handlePreview = async (reportId) => {
    setIsLoadingPreview(true);
    setError(null);
    try {
      const detail = await fetchReport(reportId);
      setActivePreview(detail);
      window.scrollTo({ top: 340, behavior: 'smooth' });
    } catch (err) {
      setError(err.message || 'Failed to load report details');
    } finally {
      setIsLoadingPreview(false);
    }
  };

  // Handle PDF download – fetches binary PDF Blob and triggers browser save dialog
  const handlePdfDownload = async (reportId) => {
    setDownloadError(null);
    setDownloadingId(reportId);
    try {
      await downloadReport(reportId);
    } catch (err) {
      setDownloadError(err.message || 'PDF download failed');
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Error Alert */}
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

      {/* Download Error Alert */}
      {downloadError && (
        <div className="p-3 bg-[#fee2e2] border border-[#ef4444]/40 text-[#991b1b] rounded-sm text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-[#991b1b]" />
            <span className="font-mono">PDF download error: {downloadError}</span>
          </div>
          <button
            onClick={() => setDownloadError(null)}
            className="text-[#991b1b] hover:text-[#7f1d1d] font-bold text-sm ml-2"
          >
            &times;
          </button>
        </div>
      )}

      {/* Single-Purpose Evidence Report Generator */}
      <Card
        title="Forensic Evidence Report Generator"
        subtitle="Select an acquired evidence artifact to generate a certified forensic PDF dossier"
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={loadData}
              disabled={isLoading || isGenerating}
              className="p-1.5 text-[#536050] hover:text-[#111813] hover:bg-[#eaede8] rounded-sm border border-[#d7ded4] transition-colors disabled:opacity-50"
              title="Refresh repository"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
            <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
              Scope: Evidence Dossier
            </div>
          </div>
        }
      >
        <form onSubmit={handleGenerate} className="space-y-4">
          {/* Evidence Selector Dropdown */}
          <div>
            <label className="block text-xs font-semibold text-[#111813] mb-1.5 uppercase tracking-wider">
              Select Target Evidence Artifact *
            </label>
            {isLoading ? (
              <div className="h-9 flex items-center px-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050]">
                Loading registered evidence items...
              </div>
            ) : evidenceList.length === 0 ? (
              <div className="h-9 flex items-center px-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050]">
                No evidence records registered yet. Ingest artifacts in Evidence Management before generating a report.
              </div>
            ) : (
              <select
                value={selectedEvidenceId}
                onChange={(e) => setSelectedEvidenceId(e.target.value)}
                disabled={isGenerating}
                className="w-full h-9 px-3 text-xs bg-white border border-[#bdc7ba] rounded-sm focus:outline-none focus:border-[#1a5935] text-[#111813] font-mono"
              >
                {evidenceList.map((ev) => (
                  <option key={ev.evidence_id} value={ev.evidence_id}>
                    {ev.evidence_id} — {ev.file_name} ({formatBytes(ev.file_size_bytes)}) [{ev.evidence_type}] [{ev.status}]
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Selected Evidence Metadata Snapshot */}
          {selectedEvidence && (
            <div className="bg-[#faf8f3] border border-[#d7ded4] p-3 rounded-sm text-xs grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div>
                <span className="text-[#6c7a68] uppercase text-[10px] font-bold block">Status</span>
                <div className="mt-0.5">
                  <StatusBadge status={selectedEvidence.status} />
                </div>
              </div>
              <div>
                <span className="text-[#6c7a68] uppercase text-[10px] font-bold block">Artifact File</span>
                <span className="font-mono text-[#111813] font-medium truncate mt-0.5 block">
                  {selectedEvidence.file_name} ({selectedEvidence.evidence_type})
                </span>
              </div>
              <div>
                <span className="text-[#6c7a68] uppercase text-[10px] font-bold block">Source Host</span>
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

          {/* Optional Metadata Inputs */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1 border-t border-[#eaede8]">
            <div>
              <label className="block text-[11px] font-semibold text-[#111813] mb-1 uppercase tracking-wider">
                Report Title (Optional)
              </label>
              <input
                type="text"
                placeholder={`Forensic Dossier — ${selectedEvidenceId || 'EVD-...'}`}
                value={reportTitle}
                onChange={(e) => setReportTitle(e.target.value)}
                className="w-full h-8 px-2.5 text-xs bg-white border border-[#bdc7ba] rounded-sm focus:outline-none focus:border-[#1a5935]"
              />
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-[#111813] mb-1 uppercase tracking-wider">
                Examiner Designation
              </label>
              <input
                type="text"
                value={examinerName}
                onChange={(e) => setExaminerName(e.target.value)}
                className="w-full h-8 px-2.5 text-xs bg-white border border-[#bdc7ba] rounded-sm focus:outline-none focus:border-[#1a5935]"
              />
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-[#111813] mb-1 uppercase tracking-wider">
                Case / Incident Notes (Optional)
              </label>
              <input
                type="text"
                placeholder="Case ticket, incident number..."
                value={examinerNotes}
                onChange={(e) => setExaminerNotes(e.target.value)}
                className="w-full h-8 px-2.5 text-xs bg-white border border-[#bdc7ba] rounded-sm focus:outline-none focus:border-[#1a5935]"
              />
            </div>
          </div>

          {/* Action Row */}
          <div className="flex justify-end pt-1">
            <button
              type="submit"
              disabled={isGenerating || !selectedEvidenceId || evidenceList.length === 0}
              className="flex items-center gap-2 bg-[#1a5935] hover:bg-[#144629] text-white px-5 py-2 rounded-sm text-xs font-semibold tracking-wide transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-none"
            >
              {isGenerating ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Compiling Evidence Data & Rendering PDF...</span>
                </>
              ) : (
                <>
                  <FileText className="w-4 h-4" />
                  <span>Generate Evidence Report</span>
                </>
              )}
            </button>
          </div>
        </form>
      </Card>

      {/* Report Preview Card */}
      {activePreview && (
        <Card
          title={`Report Preview: ${activePreview.title}`}
          subtitle={`Report Ref: ${activePreview.report_id} — Generated at ${activePreview.generated_at}`}
          action={
            <div className="flex items-center gap-2">
              <button
                onClick={() => handlePdfDownload(activePreview.report_id)}
                disabled={downloadingId === activePreview.report_id}
                className="flex items-center gap-1.5 bg-[#1a5935] hover:bg-[#144629] text-white px-3 py-1 rounded-sm text-xs font-semibold transition-colors disabled:opacity-60"
                title="Download verified PDF dossier"
              >
                {downloadingId === activePreview.report_id ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Download className="w-3.5 h-3.5" />
                )}
                <span>
                  Download PDF{activePreview.file_size_bytes > 0 ? ` (${formatBytes(activePreview.file_size_bytes)})` : ''}
                </span>
              </button>
              <button
                onClick={() => setActivePreview(null)}
                className="p-1 text-[#536050] hover:text-[#111813] hover:bg-[#eaede8] rounded-sm border border-[#d7ded4]"
                title="Close preview"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          }
        >
          {activePreview.summary_data ? (
            <div className="space-y-4 text-xs">
              {/* Executive Summary Box */}
              <div className="p-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm">
                <span className="text-[10px] font-bold uppercase tracking-wider text-[#6c7a68] block mb-1">
                  1. Executive Forensic Summary
                </span>
                <p className="text-[#111813] leading-relaxed">
                  {activePreview.summary_data.summary}
                </p>
                {activePreview.notes && (
                  <p className="text-[11px] text-[#536050] mt-1.5 font-mono">
                    <strong>Examiner Note:</strong> {activePreview.notes}
                  </p>
                )}
              </div>

              {/* Evidence Attributes & Cryptography Grid */}
              {activePreview.summary_data.evidence && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Provenance */}
                    <div className="border border-[#d7ded4] p-3 rounded-sm bg-white space-y-2">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-[#6c7a68] block">
                        2. Evidence Provenance & Details
                      </span>
                      <div className="space-y-1 font-mono text-[11px]">
                        <div><strong className="text-[#536050]">Identifier:</strong> {activePreview.summary_data.evidence.evidence_id}</div>
                        <div><strong className="text-[#536050]">Filename:</strong> {activePreview.summary_data.evidence.file_name}</div>
                        <div><strong className="text-[#536050]">Type:</strong> {activePreview.summary_data.evidence.evidence_type}</div>
                        <div><strong className="text-[#536050]">File Size:</strong> {formatBytes(activePreview.summary_data.evidence.file_size_bytes)}</div>
                        <div><strong className="text-[#536050]">Source Device:</strong> {activePreview.summary_data.evidence.source_device}</div>
                        <div><strong className="text-[#536050]">Collector:</strong> {activePreview.summary_data.evidence.collector_id}</div>
                        <div><strong className="text-[#536050]">Acquired:</strong> {activePreview.summary_data.evidence.collected_at}</div>
                      </div>
                    </div>

                    {/* Cryptography */}
                    <div className="border border-[#d7ded4] p-3 rounded-sm bg-white space-y-2">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-[#6c7a68] block">
                        3. Cryptographic Verification Ledger
                      </span>
                      <div className="space-y-1.5 text-[11px]">
                        <div>
                          <span className="text-[#536050] block font-semibold text-[10px] uppercase">SHA-256 Plaintext Digest</span>
                          <span className="font-mono text-[10px] text-[#111813] break-all block bg-[#faf8f3] p-1 rounded-sm border border-[#eaede8]">
                            {activePreview.summary_data.evidence.sha256_hash}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 pt-1">
                          <span className="text-[#536050] font-semibold text-[10px] uppercase">Integrity Status:</span>
                          <StatusBadge status={activePreview.summary_data.cryptography?.integrity_status} />
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[#536050] font-semibold text-[10px] uppercase">At-Rest Encryption:</span>
                          <span className="font-mono text-[11px] text-[#144629] font-semibold">
                            {activePreview.summary_data.cryptography?.encryption_status}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[#536050] font-semibold text-[10px] uppercase">Digital Signature:</span>
                          <span className="font-mono text-[11px] text-[#111813]">
                            {activePreview.summary_data.cryptography?.signature_status}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* PCAP Packet Analysis & Findings */}
                  <div className="border border-[#d7ded4] rounded-sm overflow-hidden bg-white">
                    <div className="p-2.5 bg-[#faf8f3] border-b border-[#d7ded4] flex items-center justify-between">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-[#3e483c]">
                        4. Forensic Findings & Inspection (Total: {activePreview.summary_data.analysis?.findings_count || 0})
                      </span>
                      <StatusBadge status={activePreview.summary_data.analysis?.status} />
                    </div>

                    {activePreview.summary_data.analysis?.packet_stats && (
                      <div className="p-2.5 bg-[#f0f9f3] border-b border-[#227244]/20 grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono">
                        <div><span className="text-[#536050]">Packets:</span> <strong>{activePreview.summary_data.analysis.packet_stats.packet_count}</strong></div>
                        <div><span className="text-[#536050]">Volume:</span> <strong>{formatBytes(activePreview.summary_data.analysis.packet_stats.total_bytes)}</strong></div>
                        <div><span className="text-[#536050]">Duration:</span> <strong>{activePreview.summary_data.analysis.packet_stats.duration_seconds?.toFixed(2)}s</strong></div>
                        <div><span className="text-[#536050]">Protocols:</span> <strong>{Object.keys(activePreview.summary_data.analysis.packet_stats.protocols || {}).join(', ') || 'N/A'}</strong></div>
                      </div>
                    )}

                    {activePreview.summary_data.analysis?.findings?.length > 0 ? (
                      <table className="w-full text-left text-xs">
                        <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
                          <tr>
                            <th className="py-2 px-3 font-semibold text-[10px] uppercase">Finding ID</th>
                            <th className="py-2 px-3 font-semibold text-[10px] uppercase">Severity</th>
                            <th className="py-2 px-3 font-semibold text-[10px] uppercase">Category</th>
                            <th className="py-2 px-3 font-semibold text-[10px] uppercase">Title</th>
                            <th className="py-2 px-3 font-semibold text-[10px] uppercase">Detected</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#eaede8]">
                          {activePreview.summary_data.analysis.findings.map((f) => (
                            <tr key={f.finding_id} className="hover:bg-[#faf8f3]">
                              <td className="py-2 px-3 font-mono font-bold text-[11px]">{f.finding_id}</td>
                              <td className="py-2 px-3"><StatusBadge status={f.severity} size="xs" /></td>
                              <td className="py-2 px-3 font-mono text-[11px] text-[#536050]">{f.category}</td>
                              <td className="py-2 px-3 font-medium text-[#111813]">{f.title}</td>
                              <td className="py-2 px-3 font-mono text-[10px] text-[#536050]">{f.detected_at}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <div className="p-4 text-center text-[#536050] text-xs">
                        {activePreview.summary_data.analysis?.message}
                      </div>
                    )}
                  </div>

                  {/* Chain of Custody Table */}
                  <div className="border border-[#d7ded4] rounded-sm overflow-hidden bg-white">
                    <div className="p-2.5 bg-[#faf8f3] border-b border-[#d7ded4]">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-[#3e483c]">
                        5. Chain of Custody Audit Ledger ({activePreview.summary_data.custody?.length || 0} Events)
                      </span>
                    </div>
                    {activePreview.summary_data.custody?.length > 0 ? (
                      <table className="w-full text-left text-xs">
                        <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
                          <tr>
                            <th className="py-2 px-3 font-semibold text-[10px] uppercase">Timestamp</th>
                            <th className="py-2 px-3 font-semibold text-[10px] uppercase">Action</th>
                            <th className="py-2 px-3 font-semibold text-[10px] uppercase">Actor</th>
                            <th className="py-2 px-3 font-semibold text-[10px] uppercase">Location</th>
                            <th className="py-2 px-3 font-semibold text-[10px] uppercase">Notes</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#eaede8]">
                          {activePreview.summary_data.custody.map((c) => (
                            <tr key={c.id} className="hover:bg-[#faf8f3]">
                              <td className="py-2 px-3 font-mono text-[10px] text-[#536050] whitespace-nowrap">{c.timestamp}</td>
                              <td className="py-2 px-3 font-semibold text-[11px] text-[#111813]">{c.action}</td>
                              <td className="py-2 px-3 font-mono text-[11px] text-[#3e483c]">{c.actor}</td>
                              <td className="py-2 px-3 font-mono text-[11px] text-[#536050] truncate max-w-[150px]">{c.location}</td>
                              <td className="py-2 px-3 text-[11px] text-[#3e483c]">{c.notes}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <div className="p-3 text-center text-[#536050] text-xs">No chain of custody records.</div>
                    )}
                  </div>
                </div>
              )}

              {/* Forensic Scope & Limitations */}
              <div className="p-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-[11px] text-[#536050]">
                <span className="font-bold text-[#111813] block mb-0.5">Forensic Methodology & Limitations:</span>
                {activePreview.summary_data.limitations}
              </div>
            </div>
          ) : (
            <div className="p-4 text-center text-[#536050] text-xs">
              Preview data loading or unavailable. You can download the generated PDF directly using the action button above.
            </div>
          )}
        </Card>
      )}

      {/* Historical Generated Reports Ledger Card */}
      <Card
        title="Forensic Evidence Reports History"
        subtitle="Chronological audit log of generated evidence dossiers and exported PDF documents"
        action={
          <div className="text-xs font-mono text-[#536050] bg-[#faf8f3] px-2.5 py-1 border border-[#d7ded4] rounded-sm">
            Total Reports: <span className="font-bold text-[#111813]">{reportsList.length}</span>
          </div>
        }
      >
        <div className="border border-[#d7ded4] rounded-sm overflow-hidden bg-white">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
              <tr>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Report ID</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Title / Dossier</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Evidence Target</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">File Size</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Generated (UTC)</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#eaede8] bg-white">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[#536050]">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-[#1a5935]" />
                      <span>Loading reports history...</span>
                    </div>
                  </td>
                </tr>
              ) : reportsList.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-14 text-center text-[#536050]">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <FileText className="w-7 h-7 text-[#94a190]" />
                      <p className="text-sm font-semibold text-[#111813]">0 Evidence Reports Generated</p>
                      <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                        No reports have been generated yet. Select an evidence artifact from the dropdown above and click "Generate Evidence Report".
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                reportsList.map((rpt) => (
                  <tr key={rpt.report_id} className="hover:bg-[#faf8f3] transition-colors">
                    <td className="py-2.5 px-3 font-mono font-bold text-[#111813] whitespace-nowrap">
                      {rpt.report_id}
                    </td>
                    <td className="py-2.5 px-3 font-medium text-[#111813]">
                      {rpt.title}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-[#144629] font-semibold whitespace-nowrap">
                      {rpt.evidence_id || 'N/A'}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-[#536050] whitespace-nowrap">
                      {formatBytes(rpt.file_size_bytes)}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-[#111813] whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5 text-[#6c7a68]" />
                        <span>{rpt.generated_at ? new Date(rpt.generated_at).toUTCString() : 'N/A'}</span>
                      </div>
                    </td>
                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handlePreview(rpt.report_id)}
                          disabled={isLoadingPreview}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-sm border border-[#bdc7ba] hover:bg-[#eaede8] text-[#111813] font-semibold text-[11px] transition-colors"
                          title="Preview report"
                        >
                          <Eye className="w-3.5 h-3.5 text-[#536050]" />
                          <span>Preview</span>
                        </button>
                        <button
                          onClick={() => handlePdfDownload(rpt.report_id)}
                          disabled={downloadingId === rpt.report_id}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-sm bg-[#1a5935] hover:bg-[#144629] text-white font-semibold text-[11px] transition-colors disabled:opacity-60"
                          title="Download PDF"
                        >
                          {downloadingId === rpt.report_id ? (
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <Download className="w-3.5 h-3.5" />
                          )}
                          <span>PDF</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
