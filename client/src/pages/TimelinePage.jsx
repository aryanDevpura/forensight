import React, { useState, useEffect, useCallback } from 'react';
import { Card } from '../components/common/Card';
import { StatusBadge } from '../components/common/StatusBadge';
import { fetchEvidence, fetchTimeline } from '../api/client';
import {
  History,
  RefreshCw,
  AlertTriangle,
  Network,
  ShieldAlert,
  ArrowRight,
  Clock,
  Layers,
  Activity,
  Tag,
} from 'lucide-react';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function TimelinePage() {
  const [evidenceList, setEvidenceList] = useState([]);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState('');
  const [timelineEvents, setTimelineEvents] = useState([]);
  const [isLoadingEvidence, setIsLoadingEvidence] = useState(true);
  const [isLoadingTimeline, setIsLoadingTimeline] = useState(false);
  const [error, setError] = useState(null);

  // Load registered evidence items
  const loadEvidence = useCallback(async () => {
    setIsLoadingEvidence(true);
    setError(null);
    try {
      const records = await fetchEvidence();
      setEvidenceList(records);

      if (records.length > 0 && !selectedEvidenceId) {
        // Prefer defaulting to first analyzed PCAP, or first PCAP, or first item
        const analyzedPcap = records.find(
          (e) =>
            ['PCAP', 'PCAPNG'].includes((e.evidence_type || '').toUpperCase()) &&
            e.status === 'ANALYZED'
        );
        const anyPcap = records.find((e) =>
          ['PCAP', 'PCAPNG'].includes((e.evidence_type || '').toUpperCase())
        );
        const defaultTarget = analyzedPcap || anyPcap || records[0];
        setSelectedEvidenceId(defaultTarget.evidence_id);
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

  // Load timeline events for selected evidence
  const loadTimeline = useCallback(async (evId) => {
    if (!evId) {
      setTimelineEvents([]);
      return;
    }
    setIsLoadingTimeline(true);
    setError(null);
    try {
      const events = await fetchTimeline(evId);
      setTimelineEvents(events);
    } catch (err) {
      setError(err.message || 'Failed to fetch timeline events');
      setTimelineEvents([]);
    } finally {
      setIsLoadingTimeline(false);
    }
  }, []);

  useEffect(() => {
    if (selectedEvidenceId) {
      loadTimeline(selectedEvidenceId);
    }
  }, [selectedEvidenceId, loadTimeline]);

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
        title="Forensic Timeline Scope"
        subtitle="Select an acquired artifact to reconstruct its chronological network flows and correlated security events"
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                loadEvidence();
                if (selectedEvidenceId) loadTimeline(selectedEvidenceId);
              }}
              disabled={isLoadingEvidence || isLoadingTimeline}
              className="p-1.5 text-[#536050] hover:text-[#111813] hover:bg-[#eaede8] rounded-sm border border-[#d7ded4] transition-colors disabled:opacity-50"
              title="Reload timeline"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingEvidence || isLoadingTimeline ? 'animate-spin' : ''}`} />
            </button>
            <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
              Chronological Audit Trail
            </div>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
            <div className="md:col-span-2">
              <label className="block text-xs font-semibold text-[#111813] mb-1 uppercase tracking-wider">
                Select Evidence Target
              </label>
              {isLoadingEvidence ? (
                <div className="h-9 flex items-center px-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050]">
                  Loading registered evidence targets...
                </div>
              ) : evidenceList.length === 0 ? (
                <div className="h-9 flex items-center px-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm text-xs text-[#536050]">
                  No evidence records registered yet. Ingest artifacts in the Evidence Repository.
                </div>
              ) : (
                <select
                  value={selectedEvidenceId}
                  onChange={(e) => setSelectedEvidenceId(e.target.value)}
                  disabled={isLoadingTimeline}
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

            <div>
              <button
                onClick={() => loadTimeline(selectedEvidenceId)}
                disabled={!selectedEvidenceId || isLoadingTimeline}
                className="w-full h-9 flex items-center justify-center gap-2 bg-[#1a5935] hover:bg-[#144629] text-white px-4 rounded-sm text-xs font-semibold tracking-wide transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-none"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isLoadingTimeline ? 'animate-spin' : ''}`} />
                <span>Reconstruct Timeline</span>
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
        </div>
      </Card>

      {/* Forensic Timeline Ledger Table */}
      <Card
        title="Chronological Forensic Events"
        subtitle={
          selectedEvidenceId
            ? `Correlated network flow and security events for ${selectedEvidenceId}`
            : 'Chronological sequence of extracted network communications and threat detections'
        }
        action={
          <div className="text-xs font-mono text-[#536050] bg-[#faf8f3] px-2.5 py-1 border border-[#d7ded4] rounded-sm">
            Events Count: <span className="font-bold text-[#111813]">{timelineEvents.length}</span>
          </div>
        }
      >
        <div className="border border-[#d7ded4] rounded-sm overflow-hidden bg-white">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
              <tr>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Event ID</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Timestamp (UTC)</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Event Type</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Severity</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Network Flow / Endpoints</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Forensic Details & Metadata</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#eaede8] bg-white">
              {isLoadingTimeline ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[#536050]">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-[#1a5935]" />
                      <span>Reconstructing event timeline...</span>
                    </div>
                  </td>
                </tr>
              ) : timelineEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-14 text-center text-[#536050]">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <History className="w-7 h-7 text-[#94a190]" />
                      <p className="text-sm font-semibold text-[#111813]">Investigation Timeline Empty</p>
                      <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                        {selectedEvidence
                          ? selectedEvidence.status !== 'ANALYZED'
                            ? `Evidence ${selectedEvidence.evidence_id} has not been analyzed yet. Go to Forensic Analysis to inspect packets.`
                            : `No timeline events generated for ${selectedEvidence.evidence_id}.`
                          : 'Select an evidence artifact above to inspect its forensic timeline.'}
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                timelineEvents.map((ev) => {
                  const isFlow = ev.event_type === 'NETWORK_FLOW';
                  const isFinding = ev.event_type === 'SECURITY_FINDING';

                  let meta = {};
                  try {
                    if (ev.metadata_json) {
                      meta = JSON.parse(ev.metadata_json);
                    }
                  } catch (e) {
                    meta = {};
                  }

                  // Type badge
                  let typeBadge = (
                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm font-mono text-[11px] font-semibold bg-[#eaede8] text-[#3e483c] border border-[#bdc7ba]">
                      <Activity className="w-3.5 h-3.5 text-[#6c7a68]" />
                      {ev.event_type}
                    </span>
                  );

                  if (isFlow) {
                    typeBadge = (
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm font-mono text-[11px] font-semibold bg-[#f0f9f3] text-[#144629] border border-[#227244]/40">
                        <Network className="w-3.5 h-3.5 text-[#1a5935]" />
                        NETWORK_FLOW
                      </span>
                    );
                  } else if (isFinding) {
                    typeBadge = (
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm font-mono text-[11px] font-semibold bg-[#fef2f2] text-[#991b1b] border border-[#ef4444]/40">
                        <ShieldAlert className="w-3.5 h-3.5 text-[#b91c1c]" />
                        SECURITY_FINDING
                      </span>
                    );
                  }

                  return (
                    <tr key={ev.id} className="hover:bg-[#faf8f3] transition-colors">
                      <td className="py-2.5 px-3 font-mono font-bold text-[#111813] whitespace-nowrap">
                        {ev.event_id}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-[#111813] whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3.5 h-3.5 text-[#6c7a68]" />
                          <span>{ev.timestamp ? new Date(ev.timestamp).toUTCString() : 'N/A'}</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {typeBadge}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <StatusBadge
                          status={ev.severity}
                          label={ev.severity}
                          size="xs"
                        />
                      </td>
                      <td className="py-2.5 px-3">
                        {isFlow ? (
                          <div className="space-y-1">
                            <div className="font-mono text-[11px] font-medium text-[#111813] flex items-center gap-1.5 flex-wrap">
                              <span className="px-1.5 py-0.2 bg-[#eaede8] text-[#2c332b] rounded-sm font-semibold">
                                {meta.protocol || 'TCP'}
                              </span>
                              <span>
                                {meta.source_ip || 'N/A'}:{meta.source_port ?? 0}
                              </span>
                              <ArrowRight className="w-3 h-3 text-[#6c7a68]" />
                              <span>
                                {meta.destination_ip || 'N/A'}:{meta.destination_port ?? 0}
                              </span>
                            </div>
                            <div className="text-[10px] font-mono text-[#536050] flex items-center gap-2">
                              <span>Len: {meta.packet_length || 0}B</span>
                              {meta.tcp_flags !== undefined && meta.tcp_flags !== null && (
                                <span>Flags: 0x{meta.tcp_flags.toString(16).padStart(2, '0')}</span>
                              )}
                            </div>
                          </div>
                        ) : (
                          <div className="space-y-0.5">
                            <span className="font-semibold text-[#111813] block">
                              {ev.message}
                            </span>
                            {meta.finding_id && (
                              <div className="flex items-center gap-1 font-mono text-[10px] text-[#6c7a68]">
                                <Tag className="w-3 h-3" />
                                <span>Ref: {meta.finding_id} ({meta.finding_category})</span>
                              </div>
                            )}
                          </div>
                        )}
                      </td>
                      <td className="py-2.5 px-3 max-w-sm">
                        {isFlow ? (
                          <p className="text-[11px] text-[#536050] font-sans">
                            {ev.message}
                          </p>
                        ) : (
                          <div className="bg-[#faf8f3] p-1.5 rounded-sm border border-[#eaede8] text-[11px] font-mono text-[#3e483c] max-h-24 overflow-x-auto">
                            {meta && Object.keys(meta).length > 0
                              ? JSON.stringify(meta, null, 2)
                              : ev.message}
                          </div>
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

      {/* Forensic Correlation Pipeline Details */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 text-xs">
        <Card title="Traffic Flow Sequencing">
          <p className="text-[#536050] leading-relaxed">
            Reconstructs individual packet timestamps, source and destination IP pairs, transport protocols, and frame lengths into a unified chronological sequence.
          </p>
        </Card>
        <Card title="Threat Finding Correlation">
          <p className="text-[#536050] leading-relaxed">
            Correlates heuristic detections (port scans, cleartext credentials, anomalous vectors) at exact detection intervals, cross-referenced with underlying evidence identifiers.
          </p>
        </Card>
        <Card title="Admissibility Standard">
          <p className="text-[#536050] leading-relaxed">
            Synchronized to UTC timestamps to preserve evidence ordering and forensic reconstructibility for judicial reporting and incident post-mortems.
          </p>
        </Card>
      </div>
    </div>
  );
}
