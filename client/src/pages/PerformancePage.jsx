import React, { useState, useEffect, useCallback } from 'react';
import { Card } from '../components/common/Card';
import { StatusBadge } from '../components/common/StatusBadge';
import { fetchBenchmarks, fetchBenchmarksSummary } from '../api/client';
import {
  Gauge,
  Activity,
  Zap,
  HardDrive,
  Clock,
  Layers,
  RefreshCw,
  AlertTriangle,
  ArrowUpRight,
  ShieldCheck,
  CheckCircle2,
  FileCode,
  SlidersHorizontal,
} from 'lucide-react';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

const OPERATION_LABELS = {
  SHA256_HASHING: {
    label: 'SHA-256 Hashing',
    desc: 'Streaming chunked cryptographic digest computation',
    color: '#1a5935',
  },
  EVIDENCE_INGESTION: {
    label: 'Evidence Ingestion',
    desc: 'Disk I/O streaming, validation & DB persistence',
    color: '#2e7d32',
  },
  HMAC_VERIFICATION: {
    label: 'HMAC Verification',
    desc: 'Server-side pre-shared key signature check',
    color: '#1e40af',
  },
  AES_DECRYPTION: {
    label: 'AES-GCM Decryption',
    desc: 'Authenticated AES-256-GCM transfer payload recovery',
    color: '#7c3aed',
  },
  PCAP_ANALYSIS: {
    label: 'PCAP Analysis',
    desc: 'Binary packet parsing & threat heuristic inspection',
    color: '#b45309',
  },
};

export function PerformancePage() {
  const [benchmarks, setBenchmarks] = useState([]);
  const [summary, setSummary] = useState(null);
  const [selectedFilter, setSelectedFilter] = useState('ALL');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [listData, summaryData] = await Promise.all([
        fetchBenchmarks(selectedFilter !== 'ALL' ? { benchmark_name: selectedFilter } : {}),
        fetchBenchmarksSummary(),
      ]);
      setBenchmarks(listData);
      setSummary(summaryData);
    } catch (err) {
      setError(err.message || 'Failed to load benchmark telemetry');
    } finally {
      setIsLoading(false);
    }
  }, [selectedFilter]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Derived high-level summary cards from real summary data
  const totalRecords = summary?.total_records || 0;
  const operations = summary?.operations || {};

  // Compute total processed bytes across all operations
  const totalBytesProcessed = Object.values(operations).reduce(
    (acc, op) => acc + (op.total_bytes_processed || 0),
    0
  );

  // Calculate overall average duration across all recorded runs
  const avgOverallDuration =
    totalRecords > 0
      ? (
          Object.values(operations).reduce(
            (acc, op) => acc + (op.avg_duration_ms || 0) * (op.count || 0),
            0
          ) / totalRecords
        ).toFixed(3)
      : '0.000';

  // Find fastest operation by min_duration_ms
  let fastestOpName = 'N/A';
  let fastestDurationMs = null;
  Object.entries(operations).forEach(([name, stats]) => {
    if (stats.min_duration_ms !== undefined && stats.min_duration_ms !== null) {
      if (fastestDurationMs === null || stats.min_duration_ms < fastestDurationMs) {
        fastestDurationMs = stats.min_duration_ms;
        fastestOpName = OPERATION_LABELS[name]?.label || name;
      }
    }
  });

  // Calculate max throughput for chart scaling
  const maxThroughput = Math.max(
    ...benchmarks
      .filter((b) => b.throughput_mbps !== null && b.throughput_mbps !== undefined)
      .map((b) => b.throughput_mbps),
    10.0
  );

  // Calculate max latency for chart scaling
  const maxDuration = Math.max(
    ...benchmarks.map((b) => b.duration_ms || 0),
    1.0
  );

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

      {/* Real Performance Summary KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white border border-[#d7ded4] p-4 rounded-sm">
          <div className="flex items-center justify-between text-[#6c7a68] mb-1">
            <span className="text-[11px] uppercase tracking-wider font-semibold">Total Benchmark Records</span>
            <Gauge className="w-4 h-4 text-[#1a5935]" />
          </div>
          <div className="text-2xl font-bold font-mono text-[#111813]">
            {totalRecords.toLocaleString()}
          </div>
          <span className="text-[11px] text-[#6c7a68]">Genuine runtime measurements</span>
        </div>

        <div className="bg-white border border-[#d7ded4] p-4 rounded-sm">
          <div className="flex items-center justify-between text-[#6c7a68] mb-1">
            <span className="text-[11px] uppercase tracking-wider font-semibold">Average Duration</span>
            <Clock className="w-4 h-4 text-[#1a5935]" />
          </div>
          <div className="text-2xl font-bold font-mono text-[#111813]">
            {avgOverallDuration} <span className="text-xs font-normal text-[#536050]">ms</span>
          </div>
          <span className="text-[11px] text-[#6c7a68]">Weighted mean latency</span>
        </div>

        <div className="bg-white border border-[#d7ded4] p-4 rounded-sm">
          <div className="flex items-center justify-between text-[#6c7a68] mb-1">
            <span className="text-[11px] uppercase tracking-wider font-semibold">Fastest Operation</span>
            <Zap className="w-4 h-4 text-[#1a5935]" />
          </div>
          <div className="text-base font-bold font-mono text-[#111813] truncate" title={fastestOpName}>
            {fastestOpName}
          </div>
          <span className="text-[11px] text-[#6c7a68]">
            {fastestDurationMs !== null ? `${fastestDurationMs.toFixed(3)} ms lowest latency` : 'No runs recorded'}
          </span>
        </div>

        <div className="bg-white border border-[#d7ded4] p-4 rounded-sm">
          <div className="flex items-center justify-between text-[#6c7a68] mb-1">
            <span className="text-[11px] uppercase tracking-wider font-semibold">Total Bytes Processed</span>
            <HardDrive className="w-4 h-4 text-[#1a5935]" />
          </div>
          <div className="text-2xl font-bold font-mono text-[#111813]">
            {formatBytes(totalBytesProcessed)}
          </div>
          <span className="text-[11px] text-[#6c7a68]">Throughput volume audited</span>
        </div>
      </div>

      {/* Operation Categories Performance Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {['SHA256_HASHING', 'EVIDENCE_INGESTION', 'HMAC_VERIFICATION', 'AES_DECRYPTION', 'PCAP_ANALYSIS'].map((key) => {
          const info = OPERATION_LABELS[key];
          const stats = operations[key];

          return (
            <div key={key} className="bg-white border border-[#d7ded4] p-4 rounded-sm flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-[#111813]">
                    {info.label}
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 bg-[#faf8f3] text-[#536050] border border-[#d7ded4] rounded-sm">
                    {stats?.count || 0} run{stats?.count === 1 ? '' : 's'}
                  </span>
                </div>
                <p className="text-[11px] text-[#6c7a68] mb-3 leading-snug">{info.desc}</p>
              </div>

              <div className="pt-2 border-t border-[#eaede8] space-y-1.5 text-xs font-mono">
                <div className="flex justify-between items-center">
                  <span className="text-[#6c7a68] text-[11px]">Avg Latency:</span>
                  <span className="font-semibold text-[#111813]">
                    {stats ? `${stats.avg_duration_ms.toFixed(3)} ms` : '—'}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[#6c7a68] text-[11px]">Avg Throughput:</span>
                  <span className="font-semibold text-[#144629]">
                    {stats?.avg_throughput_mbps !== null && stats?.avg_throughput_mbps !== undefined
                      ? `${stats.avg_throughput_mbps.toFixed(2)} MB/s`
                      : 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[#6c7a68] text-[11px]">Total Volume:</span>
                  <span className="text-[#3e483c]">
                    {stats ? formatBytes(stats.total_bytes_processed) : '—'}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Visual Charts Section (Duration & Throughput) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Latency Distribution Visualizer */}
        <Card
          title="Operation Latency Comparison"
          subtitle="Real measured execution duration per benchmark operation (ms)"
          action={
            <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
              Lower is Better
            </div>
          }
        >
          {totalRecords === 0 ? (
            <div className="py-12 text-center text-[#536050]">
              <Activity className="w-6 h-6 text-[#94a190] mx-auto mb-2" />
              <p className="text-xs font-semibold text-[#111813]">No Latency Telemetry Recorded</p>
              <p className="text-[11px] text-[#6c7a68] mt-0.5">
                Execute evidence ingestion, HMAC checks, or PCAP analysis to generate real runtime latency data.
              </p>
            </div>
          ) : (
            <div className="space-y-3.5 pt-1">
              {Object.entries(operations).map(([name, stats]) => {
                const percent = Math.min(100, Math.max(4, (stats.avg_duration_ms / maxDuration) * 100));
                const label = OPERATION_LABELS[name]?.label || name;

                return (
                  <div key={name} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="font-medium text-[#111813]">{label}</span>
                      <span className="text-[#536050]">
                        avg <strong className="text-[#111813]">{stats.avg_duration_ms.toFixed(3)} ms</strong>
                        {' '}(min {stats.min_duration_ms.toFixed(3)} / max {stats.max_duration_ms.toFixed(3)})
                      </span>
                    </div>
                    <div className="h-4 bg-[#faf8f3] border border-[#d7ded4] rounded-sm overflow-hidden flex items-center p-0.5">
                      <div
                        className="h-full bg-[#1a5935] rounded-xs transition-all duration-500"
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        {/* Throughput Telemetry Visualizer */}
        <Card
          title="Throughput Telemetry Visualizer"
          subtitle="Real cryptographic and file processing rates where throughput exists (MB/s)"
          action={
            <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
              Higher is Better
            </div>
          }
        >
          {totalRecords === 0 ||
          !Object.values(operations).some((o) => o.avg_throughput_mbps !== null) ? (
            <div className="py-12 text-center text-[#536050]">
              <Activity className="w-6 h-6 text-[#94a190] mx-auto mb-2" />
              <p className="text-xs font-semibold text-[#111813]">No Throughput Rates Recorded</p>
              <p className="text-[11px] text-[#6c7a68] mt-0.5">
                Throughput benchmarks are recorded on data-stream operations (SHA-256 Hashing, Ingestion, Analysis).
              </p>
            </div>
          ) : (
            <div className="space-y-3.5 pt-1">
              {Object.entries(operations)
                .filter(([_, stats]) => stats.avg_throughput_mbps !== null && stats.avg_throughput_mbps !== undefined)
                .map(([name, stats]) => {
                  const percent = Math.min(
                    100,
                    Math.max(4, ((stats.avg_throughput_mbps || 0) / maxThroughput) * 100)
                  );
                  const label = OPERATION_LABELS[name]?.label || name;

                  return (
                    <div key={name} className="space-y-1">
                      <div className="flex justify-between text-xs font-mono">
                        <span className="font-medium text-[#111813]">{label}</span>
                        <span className="text-[#144629] font-bold">
                          {stats.avg_throughput_mbps.toFixed(2)} MB/s
                        </span>
                      </div>
                      <div className="h-4 bg-[#faf8f3] border border-[#d7ded4] rounded-sm overflow-hidden flex items-center p-0.5">
                        <div
                          className="h-full bg-[#2e7d32] rounded-xs transition-all duration-500"
                          style={{ width: `${percent}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
            </div>
          )}
        </Card>
      </div>

      {/* Individual Benchmark Records Table */}
      <Card
        title="Benchmark Execution Telemetry Ledger"
        subtitle="Chronological audit records of actual monotonic timer benchmarks stored in SQLite"
        action={
          <div className="flex items-center gap-2">
            <select
              value={selectedFilter}
              onChange={(e) => setSelectedFilter(e.target.value)}
              className="h-7 px-2 text-[11px] bg-white border border-[#bdc7ba] rounded-sm text-[#111813] font-mono focus:outline-none focus:border-[#1a5935]"
            >
              <option value="ALL">All Operations</option>
              <option value="SHA256_HASHING">SHA256_HASHING</option>
              <option value="EVIDENCE_INGESTION">EVIDENCE_INGESTION</option>
              <option value="HMAC_VERIFICATION">HMAC_VERIFICATION</option>
              <option value="AES_DECRYPTION">AES_DECRYPTION</option>
              <option value="PCAP_ANALYSIS">PCAP_ANALYSIS</option>
            </select>
            <button
              onClick={loadData}
              disabled={isLoading}
              className="p-1 text-[#536050] hover:text-[#111813] hover:bg-[#eaede8] rounded-sm border border-[#d7ded4] transition-colors disabled:opacity-50"
              title="Refresh telemetry"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        }
      >
        <div className="border border-[#d7ded4] rounded-sm overflow-hidden bg-white">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
              <tr>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Benchmark Name</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Evidence Association</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Sample Size</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Duration</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Throughput</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Environment / System Info</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Recorded At (UTC)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#eaede8] bg-white">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[#536050]">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-[#1a5935]" />
                      <span>Loading benchmark telemetry records...</span>
                    </div>
                  </td>
                </tr>
              ) : benchmarks.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-14 text-center text-[#536050]">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <Gauge className="w-7 h-7 text-[#94a190]" />
                      <p className="text-sm font-semibold text-[#111813]">No Benchmark Telemetry Recorded</p>
                      <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                        The benchmark registry is empty. Ingesting artifacts, verifying HMAC signatures, or running PCAP packet dissections will automatically log high-resolution empirical timer measurements here.
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                benchmarks.map((b) => (
                  <tr key={b.id} className="hover:bg-[#faf8f3] transition-colors">
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className="font-mono text-[11px] font-bold text-[#111813] px-1.5 py-0.5 bg-[#eaede8] rounded-sm border border-[#d7ded4]">
                        {b.benchmark_name}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-[#536050] whitespace-nowrap">
                      {b.evidence_id || <span className="text-[#94a190] italic">None</span>}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[#111813] whitespace-nowrap">
                      {formatBytes(b.sample_size_bytes)}
                    </td>
                    <td className="py-2.5 px-3 font-mono font-semibold text-[#111813] whitespace-nowrap">
                      {b.duration_ms.toFixed(3)} ms
                    </td>
                    <td className="py-2.5 px-3 font-mono whitespace-nowrap">
                      {b.throughput_mbps !== null && b.throughput_mbps !== undefined ? (
                        <span className="text-[#144629] font-bold">
                          {b.throughput_mbps.toFixed(2)} MB/s
                        </span>
                      ) : (
                        <span className="text-[#94a190] italic">N/A</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-[#536050] text-[11px] max-w-xs truncate" title={b.system_info || ''}>
                      <span className="font-mono">{b.system_info || 'Local Workstation'}</span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-[#536050] whitespace-nowrap">
                      {b.recorded_at ? new Date(b.recorded_at).toUTCString() : 'N/A'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Forensic Rigor Methodology */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 text-xs">
        <Card title="Monotonic Time Precision">
          <p className="text-[#536050] leading-relaxed">
            All benchmarks utilize high-resolution monotonic clock measurements (<code className="font-mono text-[11px] text-[#111813]">time.perf_counter()</code>) to eliminate susceptibility to NTP clock jumps and system sleep intervals.
          </p>
        </Card>
        <Card title="Zero Simulation Guarantee">
          <p className="text-[#536050] leading-relaxed">
            Displayed throughput rates and latency values represent genuine CPU execution results against real disk payloads, cryptographic hashes, and packet dissect buffers.
          </p>
        </Card>
        <Card title="Auditable Performance Measurement">
          <p className="text-[#536050] leading-relaxed">
            Benchmark records provide an auditable measurement of processing overhead and integrity-verification performance across system operations.
          </p>
        </Card>
      </div>
    </div>
  );
}
