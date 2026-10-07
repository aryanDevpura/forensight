import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Card } from '../components/common/Card';
import { StatusBadge } from '../components/common/StatusBadge';
import { fetchEvidence, uploadEvidence } from '../api/client';
import { Upload, Inbox, CheckCircle2, AlertTriangle, FileCode, RefreshCw, X } from 'lucide-react';

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function EvidencePage({ onEvidenceUploaded }) {
  const [evidenceList, setEvidenceList] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isUploading, setIsUploading] = useState(false);
  const [showUploadForm, setShowUploadForm] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [sourceDevice, setSourceDevice] = useState('local-workstation');
  const [collectorId, setCollectorId] = useState('collector-node-01');
  const [description, setDescription] = useState('');
  const [successMessage, setSuccessMessage] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const fileInputRef = useRef(null);

  const loadEvidence = useCallback(async () => {
    setIsLoading(true);
    try {
      const records = await fetchEvidence();
      setEvidenceList(records);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to load evidence records');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadEvidence();
  }, [loadEvidence]);

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setErrorMessage(null);
    }
  };

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMessage('Please select a forensic artifact file to upload.');
      return;
    }

    setIsUploading(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('source_device', sourceDevice);
    if (collectorId) formData.append('collector_id', collectorId);
    if (description) formData.append('description', description);

    try {
      const result = await uploadEvidence(formData);
      setSuccessMessage(
        `Artifact successfully ingested! Evidence ID: ${result.evidence_id} • SHA-256: ${result.sha256_hash.slice(0, 16)}...`
      );
      // Reset form
      setSelectedFile(null);
      setDescription('');
      if (fileInputRef.current) fileInputRef.current.value = '';
      setShowUploadForm(false);

      // Automatically refresh the table
      await loadEvidence();

      // Trigger app-level dashboard stats refresh
      if (onEvidenceUploaded) {
        onEvidenceUploaded();
      }
    } catch (err) {
      setErrorMessage(err.message || 'Failed to ingest evidence artifact');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Success Notification */}
      {successMessage && (
        <div className="p-3.5 bg-[#f0f9f3] border border-[#227244]/40 rounded-sm text-[#144629] text-xs flex items-start justify-between gap-3">
          <div className="flex items-start gap-2.5">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-[#1a5935] mt-0.5" />
            <div>
              <div className="font-bold text-[#144629]">Acquisition Hashing Complete</div>
              <div className="text-[11px] text-[#227244] mt-0.5 font-mono break-all">{successMessage}</div>
            </div>
          </div>
          <button
            onClick={() => setSuccessMessage(null)}
            className="text-[#227244] hover:text-[#144629] text-xs"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Error Notification */}
      {errorMessage && (
        <div className="p-3.5 bg-[#fee2e2] border border-[#ef4444] rounded-sm text-[#991b1b] text-xs flex items-start justify-between gap-3">
          <div className="flex items-start gap-2.5">
            <AlertTriangle className="w-4 h-4 shrink-0 text-[#991b1b] mt-0.5" />
            <div>
              <div className="font-bold text-[#7f1d1d]">Ingestion Error</div>
              <div className="text-[11px] text-[#991b1b] mt-0.5">{errorMessage}</div>
            </div>
          </div>
          <button
            onClick={() => setErrorMessage(null)}
            className="text-[#991b1b] hover:text-[#7f1d1d] text-xs"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Upload Panel (Collapsible / Modal section) */}
      {showUploadForm && (
        <Card
          title="Upload Evidence Artifact"
          subtitle="Ingest raw forensic files and compute SHA-256 acquisition hash"
          action={
            <button
              onClick={() => {
                setShowUploadForm(false);
                setErrorMessage(null);
              }}
              className="text-[#536050] hover:text-[#111813] text-xs font-mono"
            >
              [Close]
            </button>
          }
        >
          <form onSubmit={handleUploadSubmit} className="space-y-4 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block font-semibold text-[#111813] mb-1">
                  Forensic Artifact File <span className="text-[#991b1b]">*</span>
                </label>
                <input
                  ref={fileInputRef}
                  type="file"
                  onChange={handleFileChange}
                  disabled={isUploading}
                  className="w-full text-xs font-mono text-[#111813] bg-[#faf8f3] border border-[#d7ded4] rounded-sm p-2 file:mr-3 file:py-1 file:px-2.5 file:rounded-sm file:border-0 file:text-xs file:font-semibold file:bg-[#1b5e34] file:text-white hover:file:bg-[#144629] cursor-pointer"
                />
                <p className="text-[10px] text-[#536050] mt-1 font-sans">
                  Supported: PCAP, PCAPNG, log, txt, csv, evtx, images, audio, video, PDF, DOC, DOCX, archives
                </p>
              </div>

              <div>
                <label className="block font-semibold text-[#111813] mb-1">
                  Source Device / Workstation
                </label>
                <input
                  type="text"
                  value={sourceDevice}
                  onChange={(e) => setSourceDevice(e.target.value)}
                  disabled={isUploading}
                  placeholder="e.g. sensor-alpha-01, endpoint-192.168.1.10"
                  className="w-full text-xs font-mono text-[#111813] bg-[#faf8f3] border border-[#d7ded4] rounded-sm p-2"
                />
              </div>

              <div>
                <label className="block font-semibold text-[#111813] mb-1">
                  Collector Node ID
                </label>
                <input
                  type="text"
                  value={collectorId}
                  onChange={(e) => setCollectorId(e.target.value)}
                  disabled={isUploading}
                  placeholder="e.g. collector-node-01"
                  className="w-full text-xs font-mono text-[#111813] bg-[#faf8f3] border border-[#d7ded4] rounded-sm p-2"
                />
              </div>

              <div>
                <label className="block font-semibold text-[#111813] mb-1">
                  Case Description / Notes (Optional)
                </label>
                <input
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  disabled={isUploading}
                  placeholder="e.g. Perimeter gateway packet capture during incident window"
                  className="w-full text-xs text-[#111813] bg-[#faf8f3] border border-[#d7ded4] rounded-sm p-2 font-sans"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2 border-t border-[#eaede8]">
              <button
                type="button"
                onClick={() => {
                  setShowUploadForm(false);
                  setSelectedFile(null);
                  if (fileInputRef.current) fileInputRef.current.value = '';
                }}
                disabled={isUploading}
                className="px-3 py-1.5 bg-[#f4f1ea] hover:bg-[#eaede8] text-[#111813] text-xs font-medium rounded-sm border border-[#bdc7ba] transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isUploading || !selectedFile}
                className="inline-flex items-center gap-1.5 px-4 py-1.5 bg-[#1b5e34] hover:bg-[#144629] disabled:opacity-50 text-white text-xs font-medium rounded-sm border border-[#144629] transition-colors"
              >
                {isUploading ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Streaming & Calculating SHA-256...</span>
                  </>
                ) : (
                  <>
                    <Upload className="w-3.5 h-3.5" />
                    <span>Upload & Ingest Evidence</span>
                  </>
                )}
              </button>
            </div>
          </form>
        </Card>
      )}

      {/* Main Evidence Registry Table */}
      <Card
        title="Evidence Registry"
        subtitle={`Catalog of forensic artifacts stored in ./storage/evidence (${evidenceList.length} items registered)`}
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={loadEvidence}
              disabled={isLoading}
              title="Refresh evidence table"
              className="p-1.5 bg-[#f4f1ea] hover:bg-[#eaede8] text-[#536050] hover:text-[#111813] rounded-sm border border-[#bdc7ba] transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={() => {
                setShowUploadForm(!showUploadForm);
                setErrorMessage(null);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#1b5e34] hover:bg-[#144629] text-white text-xs font-medium rounded-sm border border-[#144629] transition-colors"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>{showUploadForm ? 'Hide Upload Panel' : 'Upload Evidence'}</span>
            </button>
          </div>
        }
      >
        <div className="border border-[#d7ded4] rounded-sm overflow-x-auto bg-white">
          <table className="w-full text-left text-xs min-w-[800px]">
            <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
              <tr>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Evidence ID</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">File Name</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Type</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Source</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Collected At</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Size</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">SHA-256 / Integrity</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#eaede8] bg-white">
              {isLoading && evidenceList.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-10 text-center text-[#536050]">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-[#1b5e34]" />
                      <span>Loading evidence catalog...</span>
                    </div>
                  </td>
                </tr>
              ) : evidenceList.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-14 text-center text-[#536050]">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <Inbox className="w-7 h-7 text-[#94a190]" />
                      <p className="text-sm font-semibold text-[#111813]">No Evidence Registered</p>
                      <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                        The evidence storage directory is currently empty. Click <strong className="text-[#111813]">Upload Evidence</strong> above to ingest PCAP network captures, system logs, memory dumps, or forensic disk images.
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                evidenceList.map((item) => (
                  <tr key={item.id || item.evidence_id} className="hover:bg-[#faf8f3] transition-colors">
                    <td className="py-2.5 px-3 font-mono text-[11px] font-semibold text-[#111813] whitespace-nowrap">
                      {item.evidence_id}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-xs text-[#111813] font-medium whitespace-nowrap">
                      <span className="flex items-center gap-1.5">
                        <FileCode className="w-3.5 h-3.5 text-[#536050] shrink-0" />
                        <span title={item.file_name}>{item.file_name}</span>
                      </span>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className="px-1.5 py-0.5 rounded-sm bg-[#eaede8] text-[#3e483c] font-mono text-[10px] font-semibold">
                        {item.evidence_type}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-xs text-[#536050] whitespace-nowrap">
                      {item.source_device}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-[#536050] whitespace-nowrap">
                      {item.collected_at
                        ? new Date(item.collected_at).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
                        : 'N/A'}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-xs text-[#111813] whitespace-nowrap">
                      {formatBytes(item.file_size_bytes)}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-[#111813] whitespace-nowrap">
                      <span
                        className="bg-[#faf8f3] px-1.5 py-0.5 rounded-sm border border-[#d7ded4] select-all cursor-text"
                        title={`Full SHA-256 Digest:\n${item.sha256_hash}`}
                      >
                        {item.sha256_hash.slice(0, 12)}...{item.sha256_hash.slice(-8)}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <StatusBadge
                        status="standby"
                        label={item.status || 'ACQUIRED'}
                        size="xs"
                      />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
        <Card title="Artifact Intake Pipeline">
          <ul className="space-y-2 text-[#3e483c]">
            <li className="flex items-start gap-2">
              <span className="font-mono text-[#536050]">•</span>
              <span><strong>Storage Path:</strong> Stored locally under <code className="bg-[#faf8f3] border border-[#d7ded4] px-1 py-0.5 rounded-sm font-mono text-[11px] text-[#111813]">server/storage/evidence</code></span>
            </li>
            <li className="flex items-start gap-2">
              <span className="font-mono text-[#536050]">•</span>
              <span><strong>Supported Formats:</strong> PCAP, PCAPNG, log, txt, json, csv, xml, evtx, images, audio, video, PDF, DOC, DOCX, archives</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="font-mono text-[#536050]">•</span>
              <span><strong>Integrity Guarantee:</strong> Streaming SHA-256 acquisition hashes calculated with chunking upon ingest</span>
            </li>
          </ul>
        </Card>

        <Card title="Admissibility Standard">
          <p className="text-[#536050] leading-relaxed">
            All registered evidence artifacts retain immutable provenance records documenting acquisition timestamp, acquiring collector ID, physical byte size, and SHA-256 cryptographic signatures. Initial integrity status is set to ACQUIRED.
          </p>
        </Card>
      </div>
    </div>
  );
}
