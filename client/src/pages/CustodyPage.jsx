import React, { useState, useEffect, useCallback } from 'react';
import { Card } from '../components/common/Card';
import { StatusBadge } from '../components/common/StatusBadge';
import { fetchEvidence, fetchCustodyChain } from '../api/client';
import {
  Link as LinkIcon,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  ShieldCheck,
  Search,
  FileCheck2,
  Clock,
  User,
  MapPin,
  FileText,
} from 'lucide-react';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function CustodyPage() {
  const [evidenceList, setEvidenceList] = useState([]);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState('');
  const [custodyRecords, setCustodyRecords] = useState([]);
  const [isLoadingEvidence, setIsLoadingEvidence] = useState(true);
  const [isLoadingCustody, setIsLoadingCustody] = useState(false);
  const [error, setError] = useState(null);

  // Load registered evidence items
  const loadEvidence = useCallback(async () => {
    setIsLoadingEvidence(true);
    setError(null);
    try {
      const records = await fetchEvidence();
      setEvidenceList(records);

      if (records.length > 0 && !selectedEvidenceId) {
        setSelectedEvidenceId(records[0].evidence_id);
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

  // Load custody history for selected evidence item
  const loadCustody = useCallback(async (evId) => {
    if (!evId) {
      setCustodyRecords([]);
      return;
    }
    setIsLoadingCustody(true);
    setError(null);
    try {
      const chain = await fetchCustodyChain(evId);
      setCustodyRecords(chain);
    } catch (err) {
      setError(err.message || 'Failed to fetch chain of custody history');
      setCustodyRecords([]);
    } finally {
      setIsLoadingCustody(false);
    }
  }, []);

  useEffect(() => {
    if (selectedEvidenceId) {
      loadCustody(selectedEvidenceId);
    }
  }, [selectedEvidenceId, loadCustody]);

  const selectedEvidence = evidenceList.find((e) => e.evidence_id === selectedEvidenceId);

  return (
    <div className="space-y-5">
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

      {/* Target Evidence Selection Console */}
      <Card
        title="Chain of Custody Target Evidence"
        subtitle="Select an acquired digital artifact to inspect its tamper-evident audit history"
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                loadEvidence();
                if (selectedEvidenceId) loadCustody(selectedEvidenceId);
              }}
              disabled={isLoadingEvidence || isLoadingCustody}
              className="p-1.5 text-[#536050] hover:text-[#111813] hover:bg-[#eaede8] rounded-sm border border-[#d7ded4] transition-colors disabled:opacity-50"
              title="Refresh custody history"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingEvidence || isLoadingCustody ? 'animate-spin' : ''}`} />
            </button>
            <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
              Standard: FRE Rule 901
            </div>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-[#111813] mb-1 uppercase tracking-wider">
                Select Evidence Item
              </label>
              {isLoadingEvidence ? (
                <div className="h-9 flex items-center px-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050]">
                  Loading registered evidence items...
                </div>
              ) : evidenceList.length === 0 ? (
                <div className="h-9 flex items-center px-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050]">
                  No evidence records registered yet. Ingest artifacts in the Evidence Repository.
                </div>
              ) : (
                <select
                  value={selectedEvidenceId}
                  onChange={(e) => setSelectedEvidenceId(e.target.value)}
                  disabled={isLoadingCustody}
                  className="w-full h-9 px-3 text-xs bg-white border border-[#bdc7ba] rounded-sm focus:outline-none focus:border-[#1a5935] text-[#111813] font-mono"
                >
                  {evidenceList.map((ev) => (
                    <option key={ev.evidence_id} value={ev.evidence_id}>
                      {ev.evidence_id} — {ev.file_name} ({formatBytes(ev.file_size_bytes)}) [{ev.evidence_type}]
                    </option>
                  ))}
                </select>
              )}
            </div>

            <div>
              <button
                onClick={() => loadCustody(selectedEvidenceId)}
                disabled={!selectedEvidenceId || isLoadingCustody}
                className="w-full h-9 flex items-center justify-center gap-2 bg-[#1a5935] hover:bg-[#144629] text-white px-4 rounded-sm text-xs font-semibold tracking-wide transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-none"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoadingCustody ? 'animate-spin' : ''}`} />
                <span>Fetch Custody Chain</span>
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
                <span className="text-[#6c7a68] uppercase text-[10px] font-bold block">File Name & Type</span>
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
        </div>
      </Card>

      {/* Chain of Custody Timeline / Ledger Table */}
      <Card
        title="Chain of Custody Ledger"
        subtitle={
          selectedEvidenceId
            ? `Chronological audit transactions for ${selectedEvidenceId}`
            : 'Immutable audit log verifying artifact integrity across transfer and examination stages'
        }
        action={
          <div className="text-xs font-mono text-[#536050] bg-[#faf8f3] px-2.5 py-1 border border-[#d7ded4] rounded-sm">
            Total Custody Events: <span className="font-bold text-[#111813]">{custodyRecords.length}</span>
          </div>
        }
      >
        <div className="border border-[#d7ded4] rounded-sm overflow-hidden bg-white">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
              <tr>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Event / Action</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Timestamp (UTC)</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Actor / Agent</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Evidence ID</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Storage Location</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Audit Notes & Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#eaede8] bg-white">
              {isLoadingCustody ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[#536050]">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-[#1a5935]" />
                      <span>Loading chain of custody ledger...</span>
                    </div>
                  </td>
                </tr>
              ) : custodyRecords.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-14 text-center text-[#536050]">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <LinkIcon className="w-7 h-7 text-[#94a190]" />
                      <p className="text-sm font-semibold text-[#111813]">0 Chain of Custody Records</p>
                      <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                        {selectedEvidenceId
                          ? `No custody records found for evidence item ${selectedEvidenceId}.`
                          : 'Select an evidence item above to inspect its chain-of-custody audit logs.'}
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                custodyRecords.map((record) => {
                  const isAcquired = record.action === 'ACQUIRED';
                  const isAnalyzed = record.action === 'ANALYZED';

                  // Distinct badge styles for actions
                  let actionBadge = (
                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm font-mono text-[11px] font-semibold bg-[#eaede8] text-[#3e483c] border border-[#bdc7ba]">
                      <FileCheck2 className="w-3.5 h-3.5 text-[#6c7a68]" />
                      {record.action}
                    </span>
                  );

                  if (isAcquired) {
                    actionBadge = (
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm font-mono text-[11px] font-semibold bg-[#f0f9f3] text-[#144629] border border-[#227244]/40">
                        <CheckCircle2 className="w-3.5 h-3.5 text-[#1a5935]" />
                        ACQUIRED
                      </span>
                    );
                  } else if (isAnalyzed) {
                    actionBadge = (
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm font-mono text-[11px] font-semibold bg-[#eff6ff] text-[#1e40af] border border-[#3b82f6]/40">
                        <ShieldCheck className="w-3.5 h-3.5 text-[#1e40af]" />
                        ANALYZED
                      </span>
                    );
                  }

                  return (
                    <tr key={record.id} className="hover:bg-[#faf8f3] transition-colors">
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {actionBadge}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-[#111813] whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3.5 h-3.5 text-[#6c7a68]" />
                          <span>{record.timestamp ? new Date(record.timestamp).toUTCString() : 'N/A'}</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[#111813] whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <User className="w-3.5 h-3.5 text-[#6c7a68]" />
                          <span className="font-semibold">{record.actor}</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[#536050] whitespace-nowrap">
                        {record.evidence_id}
                      </td>
                      <td className="py-2.5 px-3 text-[#536050] max-w-xs truncate" title={record.location || ''}>
                        <div className="flex items-center gap-1.5">
                          <MapPin className="w-3.5 h-3.5 shrink-0 text-[#6c7a68]" />
                          <span className="font-mono text-[11px] truncate">{record.location || 'Local Storage'}</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 max-w-md">
                        {record.notes ? (
                          <div className="bg-[#faf8f3] p-1.5 rounded-sm border border-[#eaede8] text-[11px] font-mono text-[#3e483c] break-all">
                            {record.notes}
                          </div>
                        ) : (
                          <span className="text-[#94a190] italic">No notes recorded</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Protocol & Admissibility Note */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 text-xs">
        <Card title="Cryptographic Provenance">
          <p className="text-[#536050] leading-relaxed">
            Every custody event logs the current SHA-256 digest of the physical artifact. An intact chain proves that forensic evidence was preserved without tampering.
          </p>
        </Card>
        <Card title="Automated Event Tracking">
          <p className="text-[#536050] leading-relaxed">
            Ingestion automatically commits an <span className="font-mono font-semibold text-[#144629]">ACQUIRED</span> entry. Subsequent deep packet inspections write an <span className="font-mono font-semibold text-[#1e40af]">ANALYZED</span> entry with the examining actor identifier.
          </p>
        </Card>
        <Card title="Admissibility Standard">
          <p className="text-[#536050] leading-relaxed">
            Maintains adherence to Federal Rules of Evidence Rule 901 and ISO/IEC 27037 standards for digital evidence handling and identification.
          </p>
        </Card>
      </div>
    </div>
  );
}
