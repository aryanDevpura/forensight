import React, { useState, useEffect, useCallback, useMemo } from 'react';
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
  Lock,
  Unlock,
  KeyRound,
  FileCheck,
  TrendingUp,
  BarChart3,
  Scale,
  Info,
} from 'lucide-react';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

// 7 visible operations (HMAC removed as per workflow cleanup)
const OPERATION_LABELS = {
  AES_ENCRYPTION: {
    label: 'AES-GCM Encryption',
    desc: 'Client-side authenticated symmetric payload encryption',
    color: '#9333ea',
    group: 'symmetric',
  },
  AES_DECRYPTION: {
    label: 'AES-GCM Decryption',
    desc: 'Authenticated AES-256-GCM transfer payload recovery',
    color: '#7c3aed',
    group: 'symmetric',
  },
  SHA256_HASHING: {
    label: 'SHA-256 Hashing',
    desc: 'Streaming chunked cryptographic digest computation',
    color: '#1a5935',
    group: 'hashing',
  },
  RSA_SIGNING: {
    label: 'RSA-PSS Signing',
    desc: 'Client-side digital signature generation over canonical metadata',
    color: '#0369a1',
    group: 'asymmetric',
  },
  RSA_VERIFICATION: {
    label: 'RSA-PSS Verification',
    desc: 'Server-side digital signature verification against trusted public key',
    color: '#0284c7',
    group: 'asymmetric',
  },
  EVIDENCE_INGESTION: {
    label: 'Evidence Ingestion',
    desc: 'End-to-end payload intake, disk write, validation & DB persistence',
    color: '#2e7d32',
    group: 'system',
  },
  PCAP_ANALYSIS: {
    label: 'PCAP Analysis',
    desc: 'Binary packet parsing & threat heuristic inspection',
    color: '#b45309',
    group: 'analysis',
  },
};

const SIZE_TIERS = [
  { id: 'ALL', label: 'All Sizes' },
  { id: 'TINY', label: '< 10 KB', min: 0, max: 10 * 1024 },
  { id: 'SMALL', label: '10 KB – 100 KB', min: 10 * 1024, max: 100 * 1024 },
  { id: 'MEDIUM', label: '100 KB – 1 MB', min: 100 * 1024, max: 1024 * 1024 },
  { id: 'LARGE', label: '> 1 MB', min: 1024 * 1024, max: null },
];

export function PerformancePage() {
  const [benchmarks, setBenchmarks] = useState([]);
  const [summary, setSummary] = useState(null);
  const [selectedFilter, setSelectedFilter] = useState('ALL');
  const [selectedSizeTier, setSelectedSizeTier] = useState('ALL');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const tier = SIZE_TIERS.find((t) => t.id === selectedSizeTier);
      const queryParams = { exclude_hmac: true };
      if (selectedFilter !== 'ALL') {
        queryParams.benchmark_name = selectedFilter;
      }
      if (tier && tier.min !== undefined && tier.min !== null) {
        queryParams.min_size_bytes = tier.min;
      }
      if (tier && tier.max !== undefined && tier.max !== null) {
        queryParams.max_size_bytes = tier.max;
      }

      const [listData, summaryData] = await Promise.all([
        fetchBenchmarks(queryParams),
        fetchBenchmarksSummary({ exclude_hmac: true }),
      ]);
      setBenchmarks(listData);
      setSummary(summaryData);
    } catch (err) {
      setError(err.message || 'Failed to load benchmark telemetry');
    } finally {
      setIsLoading(false);
    }
  }, [selectedFilter, selectedSizeTier]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Filter raw summary operations to only include allowed operations
  const rawOperations = summary?.operations || {};
  const operations = useMemo(() => {
    const filtered = {};
    for (const [key, stats] of Object.entries(rawOperations)) {
      if (OPERATION_LABELS[key]) {
        filtered[key] = stats;
      }
    }
    return filtered;
  }, [rawOperations]);

  // Derived high-level metrics excluding HMAC
  const totalRecords = useMemo(() => {
    return Object.values(operations).reduce((acc, op) => acc + (op.count || 0), 0);
  }, [operations]);

  const totalBytesProcessed = useMemo(() => {
    return Object.values(operations).reduce(
      (acc, op) => acc + (op.total_bytes_processed || 0),
      0
    );
  }, [operations]);

  const avgOverallDuration = useMemo(() => {
    return totalRecords > 0
      ? (
          Object.values(operations).reduce(
            (acc, op) => acc + (op.avg_duration_ms || 0) * (op.count || 0),
            0
          ) / totalRecords
        ).toFixed(3)
      : '0.000';
  }, [operations, totalRecords]);

  // Find fastest operation by min_duration_ms among active operations
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

  // Segregate operations for meaningful, readable latency comparison
  // Group A: Microsecond-to-millisecond primitives (< 10 ms typical)
  const cryptoOperations = useMemo(() => {
    return Object.entries(operations).filter(([name]) =>
      ['SHA256_HASHING', 'AES_DECRYPTION', 'RSA_VERIFICATION', 'AES_ENCRYPTION', 'RSA_SIGNING'].includes(name)
    );
  }, [operations]);

  // Group B: Macroscopic multi-stage operations (I/O, packet parsing)
  const macroOperations = useMemo(() => {
    return Object.entries(operations).filter(([name]) =>
      ['EVIDENCE_INGESTION', 'PCAP_ANALYSIS'].includes(name)
    );
  }, [operations]);

  const maxCryptoDuration = useMemo(() => {
    const vals = cryptoOperations.map(([_, s]) => s.avg_duration_ms || 0);
    return Math.max(...vals, 1.0);
  }, [cryptoOperations]);

  const maxMacroDuration = useMemo(() => {
    const vals = macroOperations.map(([_, s]) => s.avg_duration_ms || 0);
    return Math.max(...vals, 10.0);
  }, [macroOperations]);

  // Max throughput for streaming throughput chart
  const throughputOperations = useMemo(() => {
    return Object.entries(operations).filter(
      ([_, stats]) => stats.avg_throughput_mbps !== null && stats.avg_throughput_mbps !== undefined
    );
  }, [operations]);

  const maxThroughput = useMemo(() => {
    const vals = throughputOperations.map(([_, s]) => s.avg_throughput_mbps || 0);
    return Math.max(...vals, 5.0);
  }, [throughputOperations]);

  // Paired Cryptographic Operations Data
  const aesEncStats = operations['AES_ENCRYPTION'];
  const aesDecStats = operations['AES_DECRYPTION'];
  const rsaSignStats = operations['RSA_SIGNING'];
  const rsaVerifyStats = operations['RSA_VERIFICATION'];

  // Historical Trends (chronological order from filtered benchmarks)
  const chronologicalRuns = useMemo(() => {
    return [...benchmarks]
      .filter((b) => OPERATION_LABELS[b.benchmark_name])
      .reverse()
      .slice(-20); // Last 20 operations
  }, [benchmarks]);

  const maxTrendDuration = useMemo(() => {
    const vals = chronologicalRuns.map((r) => r.duration_ms || 0);
    return Math.max(...vals, 1.0);
  }, [chronologicalRuns]);

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
          <span className="text-[11px] text-[#6c7a68]">Core forensic workflow events</span>
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

      {/* Operation Categories Performance Cards (7 ForenSight Core Operations) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
        {[
          'AES_ENCRYPTION',
          'AES_DECRYPTION',
          'SHA256_HASHING',
          'RSA_SIGNING',
          'RSA_VERIFICATION',
          'EVIDENCE_INGESTION',
          'PCAP_ANALYSIS',
        ].map((key) => {
          const info = OPERATION_LABELS[key] || { label: key, desc: 'Cryptographic operation', color: '#1a5935' };
          const stats = operations[key];

          return (
            <div key={key} className="bg-white border border-[#d7ded4] p-3.5 rounded-sm flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-[#111813] truncate" title={info.label}>
                    {info.label}
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 bg-[#faf8f3] text-[#536050] border border-[#d7ded4] rounded-sm shrink-0">
                    {stats?.count || 0} run{stats?.count === 1 ? '' : 's'}
                  </span>
                </div>
                <p className="text-[10px] text-[#6c7a68] mb-2 leading-snug line-clamp-2">{info.desc}</p>
              </div>

              <div className="pt-2 border-t border-[#eaede8] space-y-1 text-xs font-mono">
                <div className="flex justify-between items-center text-[11px]">
                  <span className="text-[#6c7a68]">Avg Latency:</span>
                  <span className="font-semibold text-[#111813]">
                    {stats ? `${stats.avg_duration_ms.toFixed(3)} ms` : '—'}
                  </span>
                </div>
                <div className="flex justify-between items-center text-[11px]">
                  <span className="text-[#6c7a68]">Throughput:</span>
                  <span className="font-semibold text-[#144629]">
                    {stats?.avg_throughput_mbps !== null && stats?.avg_throughput_mbps !== undefined
                      ? `${stats.avg_throughput_mbps.toFixed(2)} MB/s`
                      : 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between items-center text-[11px]">
                  <span className="text-[#6c7a68]">Volume:</span>
                  <span className="text-[#3e483c]">
                    {stats ? formatBytes(stats.total_bytes_processed) : '—'}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Cryptographic Operation Direct Comparisons */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Symmetric Cipher Comparison: AES-256-GCM Encrypt vs Decrypt */}
        <Card
          title="Symmetric Cipher Comparison: AES-256-GCM"
          subtitle="Direct comparison of authenticated encryption vs decryption latency and throughput"
          action={
            <div className="flex items-center gap-1.5 text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
              <Scale className="w-3.5 h-3.5 text-[#1a5935]" />
              <span>Symmetric Core</span>
            </div>
          }
        >
          <div className="space-y-4 pt-1">
            <div className="grid grid-cols-2 gap-3">
              {/* Encrypt side */}
              <div className="p-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#111813] flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-[#9333ea]" />
                    Encryption
                  </span>
                  <span className="text-[10px] font-mono text-[#6c7a68]">
                    {aesEncStats?.count || 0} run{aesEncStats?.count === 1 ? '' : 's'}
                  </span>
                </div>
                <div className="space-y-1 font-mono text-xs">
                  <div className="flex justify-between">
                    <span className="text-[#6c7a68] text-[11px]">Mean Duration:</span>
                    <strong className="text-[#111813]">
                      {aesEncStats ? `${aesEncStats.avg_duration_ms.toFixed(3)} ms` : 'No data'}
                    </strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#6c7a68] text-[11px]">Throughput:</span>
                    <strong className="text-[#144629]">
                      {aesEncStats?.avg_throughput_mbps ? `${aesEncStats.avg_throughput_mbps.toFixed(2)} MB/s` : 'N/A'}
                    </strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#6c7a68] text-[11px]">Min / Max:</span>
                    <span className="text-[#536050] text-[10px]">
                      {aesEncStats ? `${aesEncStats.min_duration_ms.toFixed(2)} / ${aesEncStats.max_duration_ms.toFixed(2)} ms` : '—'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Decrypt side */}
              <div className="p-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#111813] flex items-center gap-1.5">
                    <Unlock className="w-3.5 h-3.5 text-[#7c3aed]" />
                    Decryption
                  </span>
                  <span className="text-[10px] font-mono text-[#6c7a68]">
                    {aesDecStats?.count || 0} run{aesDecStats?.count === 1 ? '' : 's'}
                  </span>
                </div>
                <div className="space-y-1 font-mono text-xs">
                  <div className="flex justify-between">
                    <span className="text-[#6c7a68] text-[11px]">Mean Duration:</span>
                    <strong className="text-[#111813]">
                      {aesDecStats ? `${aesDecStats.avg_duration_ms.toFixed(3)} ms` : 'No data'}
                    </strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#6c7a68] text-[11px]">Throughput:</span>
                    <strong className="text-[#144629]">
                      {aesDecStats?.avg_throughput_mbps ? `${aesDecStats.avg_throughput_mbps.toFixed(2)} MB/s` : 'N/A'}
                    </strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#6c7a68] text-[11px]">Min / Max:</span>
                    <span className="text-[#536050] text-[10px]">
                      {aesDecStats ? `${aesDecStats.min_duration_ms.toFixed(2)} / ${aesDecStats.max_duration_ms.toFixed(2)} ms` : '—'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Differential Ratio Bar */}
            {aesEncStats && aesDecStats ? (
              <div className="space-y-1">
                <div className="flex justify-between text-[11px] font-mono text-[#536050]">
                  <span>Encryption: {aesEncStats.avg_duration_ms.toFixed(3)} ms</span>
                  <span>Decryption: {aesDecStats.avg_duration_ms.toFixed(3)} ms</span>
                </div>
                <div className="h-3 bg-[#eaede8] rounded-xs overflow-hidden flex">
                  <div
                    className="bg-[#9333ea] h-full"
                    style={{
                      width: `${
                        (aesEncStats.avg_duration_ms /
                          (aesEncStats.avg_duration_ms + aesDecStats.avg_duration_ms || 1)) *
                        100
                      }%`,
                    }}
                    title="Encryption Ratio"
                  />
                  <div
                    className="bg-[#7c3aed] h-full"
                    style={{
                      width: `${
                        (aesDecStats.avg_duration_ms /
                          (aesEncStats.avg_duration_ms + aesDecStats.avg_duration_ms || 1)) *
                        100
                      }%`,
                    }}
                    title="Decryption Ratio"
                  />
                </div>
              </div>
            ) : (
              <p className="text-[11px] text-[#6c7a68] italic text-center py-2">
                Perform evidence ingestion or Crypto Lab decryption to record AES performance data.
              </p>
            )}
          </div>
        </Card>

        {/* Asymmetric Cryptography: RSA-PSS Signing vs Verification */}
        <Card
          title="Asymmetric Digital Signatures: RSA-PSS (2048-bit)"
          subtitle="Computational asymmetry: Private-key exponentiation vs public-key verification"
          action={
            <div className="flex items-center gap-1.5 text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
              <KeyRound className="w-3.5 h-3.5 text-[#0284c7]" />
              <span>Asymmetric Core</span>
            </div>
          }
        >
          <div className="space-y-4 pt-1">
            <div className="grid grid-cols-2 gap-3">
              {/* Signing side */}
              <div className="p-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#111813] flex items-center gap-1.5">
                    <FileCheck className="w-3.5 h-3.5 text-[#0369a1]" />
                    RSA Signing
                  </span>
                  <span className="text-[10px] font-mono text-[#6c7a68]">
                    {rsaSignStats?.count || 0} run{rsaSignStats?.count === 1 ? '' : 's'}
                  </span>
                </div>
                <div className="space-y-1 font-mono text-xs">
                  <div className="flex justify-between">
                    <span className="text-[#6c7a68] text-[11px]">Mean Duration:</span>
                    <strong className="text-[#111813]">
                      {rsaSignStats ? `${rsaSignStats.avg_duration_ms.toFixed(3)} ms` : 'No data'}
                    </strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#6c7a68] text-[11px]">Operation:</span>
                    <span className="text-[#536050] text-[10px]">Private key d</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#6c7a68] text-[11px]">Min / Max:</span>
                    <span className="text-[#536050] text-[10px]">
                      {rsaSignStats ? `${rsaSignStats.min_duration_ms.toFixed(2)} / ${rsaSignStats.max_duration_ms.toFixed(2)} ms` : '—'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Verification side */}
              <div className="p-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#111813] flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-[#0284c7]" />
                    RSA Verification
                  </span>
                  <span className="text-[10px] font-mono text-[#6c7a68]">
                    {rsaVerifyStats?.count || 0} run{rsaVerifyStats?.count === 1 ? '' : 's'}
                  </span>
                </div>
                <div className="space-y-1 font-mono text-xs">
                  <div className="flex justify-between">
                    <span className="text-[#6c7a68] text-[11px]">Mean Duration:</span>
                    <strong className="text-[#111813]">
                      {rsaVerifyStats ? `${rsaVerifyStats.avg_duration_ms.toFixed(3)} ms` : 'No data'}
                    </strong>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#6c7a68] text-[11px]">Operation:</span>
                    <span className="text-[#536050] text-[10px]">Public key e=65537</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#6c7a68] text-[11px]">Min / Max:</span>
                    <span className="text-[#536050] text-[10px]">
                      {rsaVerifyStats ? `${rsaVerifyStats.min_duration_ms.toFixed(2)} / ${rsaVerifyStats.max_duration_ms.toFixed(2)} ms` : '—'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Asymmetry Insight Note */}
            <div className="p-2.5 bg-[#faf8f3] border border-[#eaede8] rounded-sm text-[11px] text-[#536050] leading-relaxed flex items-start gap-2">
              <Info className="w-3.5 h-3.5 text-[#0284c7] shrink-0 mt-0.5" />
              <span>
                <strong>Asymmetric Inversion:</strong> RSA verification uses the small Fermat public exponent ($e=65537$), requiring only 17 modular squarings and multiplications, making verification drastically faster than private-key signing with $d$.
              </span>
            </div>
          </div>
        </Card>
      </div>

      {/* Visual Charts Section: Segmented Latency by Magnitude & Throughput */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Chart 1: Cryptographic Primitives Latency (Microsecond-to-Millisecond Scale) */}
        <Card
          title="Cryptographic Primitives Latency"
          subtitle="Focused scale (0 – 10 ms) for symmetric ciphers, hashing & digital signatures"
          action={
            <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
              &le; 10 ms Scale
            </div>
          }
        >
          {cryptoOperations.length === 0 ? (
            <div className="py-12 text-center text-[#536050]">
              <Activity className="w-6 h-6 text-[#94a190] mx-auto mb-2" />
              <p className="text-xs font-semibold text-[#111813]">No Crypto Latency Recorded</p>
            </div>
          ) : (
            <div className="space-y-3.5 pt-1">
              {cryptoOperations.map(([name, stats]) => {
                // Linear scaling relative to maxCryptoDuration with minimum visual width of 3%
                const pct = Math.min(100, Math.max(3, (stats.avg_duration_ms / maxCryptoDuration) * 100));
                const label = OPERATION_LABELS[name]?.label || name;
                const opColor = OPERATION_LABELS[name]?.color || '#1a5935';

                return (
                  <div key={name} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="font-medium text-[#111813] truncate" title={label}>{label}</span>
                      <span className="text-[#536050] shrink-0">
                        <strong className="text-[#111813]">{stats.avg_duration_ms.toFixed(3)} ms</strong>
                      </span>
                    </div>
                    <div className="h-4 bg-[#faf8f3] border border-[#d7ded4] rounded-sm overflow-hidden flex items-center p-0.5">
                      <div
                        className="h-full rounded-xs transition-all duration-500"
                        style={{ width: `${pct}%`, backgroundColor: opColor }}
                        title={`${label}: ${stats.avg_duration_ms.toFixed(4)} ms`}
                      />
                    </div>
                    <div className="flex justify-between text-[10px] font-mono text-[#6c7a68]">
                      <span>min {stats.min_duration_ms.toFixed(3)} ms</span>
                      <span>max {stats.max_duration_ms.toFixed(3)} ms</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        {/* Chart 2: Multi-Stage Workflow & File Processing Latency */}
        <Card
          title="Workflow & Analysis Latency"
          subtitle="Macroscopic scale (10 – 200 ms) for disk I/O, persistence & packet parsing"
          action={
            <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
              &gt; 10 ms Scale
            </div>
          }
        >
          {macroOperations.length === 0 ? (
            <div className="py-12 text-center text-[#536050]">
              <Activity className="w-6 h-6 text-[#94a190] mx-auto mb-2" />
              <p className="text-xs font-semibold text-[#111813]">No Workflow Latency Recorded</p>
            </div>
          ) : (
            <div className="space-y-3.5 pt-1">
              {macroOperations.map(([name, stats]) => {
                const pct = Math.min(100, Math.max(3, (stats.avg_duration_ms / maxMacroDuration) * 100));
                const label = OPERATION_LABELS[name]?.label || name;
                const opColor = OPERATION_LABELS[name]?.color || '#2e7d32';

                return (
                  <div key={name} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="font-medium text-[#111813] truncate" title={label}>{label}</span>
                      <span className="text-[#536050] shrink-0">
                        <strong className="text-[#111813]">{stats.avg_duration_ms.toFixed(2)} ms</strong>
                      </span>
                    </div>
                    <div className="h-4 bg-[#faf8f3] border border-[#d7ded4] rounded-sm overflow-hidden flex items-center p-0.5">
                      <div
                        className="h-full rounded-xs transition-all duration-500"
                        style={{ width: `${pct}%`, backgroundColor: opColor }}
                        title={`${label}: ${stats.avg_duration_ms.toFixed(2)} ms`}
                      />
                    </div>
                    <div className="flex justify-between text-[10px] font-mono text-[#6c7a68]">
                      <span>min {stats.min_duration_ms.toFixed(2)} ms</span>
                      <span>max {stats.max_duration_ms.toFixed(2)} ms</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        {/* Chart 3: Streaming Data Throughput (MB/s) */}
        <Card
          title="Streaming Throughput Telemetry"
          subtitle="Processing speed where payload streams exist (MB/s)"
          action={
            <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
              Higher is Better
            </div>
          }
        >
          {throughputOperations.length === 0 ? (
            <div className="py-12 text-center text-[#536050]">
              <Activity className="w-6 h-6 text-[#94a190] mx-auto mb-2" />
              <p className="text-xs font-semibold text-[#111813]">No Throughput Rates Recorded</p>
              <p className="text-[11px] text-[#6c7a68] mt-0.5">
                Throughput benchmarks are recorded on data-stream operations.
              </p>
            </div>
          ) : (
            <div className="space-y-3.5 pt-1">
              {throughputOperations.map(([name, stats]) => {
                const percent = Math.min(
                  100,
                  Math.max(3, ((stats.avg_throughput_mbps || 0) / maxThroughput) * 100)
                );
                const label = OPERATION_LABELS[name]?.label || name;

                return (
                  <div key={name} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="font-medium text-[#111813] truncate" title={label}>{label}</span>
                      <span className="text-[#144629] font-bold shrink-0">
                        {stats.avg_throughput_mbps.toFixed(2)} MB/s
                      </span>
                    </div>
                    <div className="h-4 bg-[#faf8f3] border border-[#d7ded4] rounded-sm overflow-hidden flex items-center p-0.5">
                      <div
                        className="h-full bg-[#1a5935] rounded-xs transition-all duration-500"
                        style={{ width: `${percent}%` }}
                        title={`${label}: ${stats.avg_throughput_mbps.toFixed(2)} MB/s`}
                      />
                    </div>
                    <div className="flex justify-between text-[10px] font-mono text-[#6c7a68]">
                      <span>{stats.count} run{stats.count === 1 ? '' : 's'}</span>
                      <span>Vol: {formatBytes(stats.total_bytes_processed)}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>

      {/* Historical Trend Timeline Card */}
      <Card
        title="Execution Latency Trends (Sequential Audit History)"
        subtitle="Chronological progression of measured durations across recent recorded benchmark events"
        action={
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
            <TrendingUp className="w-3.5 h-3.5 text-[#1a5935]" />
            <span>Last {chronologicalRuns.length} Operations</span>
          </div>
        }
      >
        {chronologicalRuns.length === 0 ? (
          <div className="py-8 text-center text-[#536050]">
            <Activity className="w-5 h-5 text-[#94a190] mx-auto mb-1.5" />
            <p className="text-xs font-semibold text-[#111813]">No Chronological History Available</p>
            <p className="text-[11px] text-[#6c7a68]">Telemetry events will automatically plot here as operations execute.</p>
          </div>
        ) : (
          <div className="space-y-4 pt-1">
            {/* SVG Sparkline/Bar Chart with relative height scaling and clear minimum visible height */}
            <div className="p-3 bg-[#faf8f3] border border-[#d7ded4] rounded-sm">
              <div className="h-32 flex items-end gap-1.5 justify-between">
                {chronologicalRuns.map((run, idx) => {
                  // Use power curve (sqrt) for trend chart heights so microsecond ops (0.02ms) are clearly visible beside 100ms I/O ops
                  const normalizedFraction = Math.max(0.02, Math.sqrt((run.duration_ms || 0) / maxTrendDuration));
                  const heightPct = Math.min(100, Math.max(6, normalizedFraction * 100));
                  const opColor = OPERATION_LABELS[run.benchmark_name]?.color || '#1a5935';

                  return (
                    <div
                      key={run.id || idx}
                      className="flex-1 flex flex-col items-center group relative h-full justify-end"
                    >
                      {/* Tooltip */}
                      <div className="absolute -top-10 bg-[#111813] text-white text-[10px] font-mono px-2.5 py-1 rounded shadow-md pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity z-20 whitespace-nowrap">
                        <div className="font-bold">{OPERATION_LABELS[run.benchmark_name]?.label || run.benchmark_name}</div>
                        <div>Duration: {run.duration_ms.toFixed(3)} ms</div>
                        <div>Payload: {formatBytes(run.sample_size_bytes)}</div>
                      </div>
                      <div
                        className="w-full rounded-t-xs hover:opacity-80 transition-all cursor-pointer"
                        style={{
                          height: `${heightPct}%`,
                          backgroundColor: opColor,
                        }}
                      />
                    </div>
                  );
                })}
              </div>
              <div className="flex justify-between items-center text-[10px] font-mono text-[#6c7a68] pt-2 border-t border-[#eaede8] mt-2">
                <span>&larr; Older events in session</span>
                <span className="italic">Square-root amplitude scale preserves microsecond visibility</span>
                <span>Most recent event &rarr;</span>
              </div>
            </div>

            {/* Legend */}
            <div className="flex flex-wrap gap-3 pt-1 text-[11px] font-mono text-[#536050]">
              {Object.entries(OPERATION_LABELS).map(([key, info]) => {
                const count = chronologicalRuns.filter((r) => r.benchmark_name === key).length;
                if (count === 0) return null;
                return (
                  <div key={key} className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-xs" style={{ backgroundColor: info.color }} />
                    <span>{info.label} ({count})</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </Card>

      {/* Individual Benchmark Records Table with Multi-Facet Filtering */}
      <Card
        title="Benchmark Execution Telemetry Ledger"
        subtitle="Chronological audit records of actual monotonic timer benchmarks stored in SQLite"
        action={
          <div className="flex flex-wrap items-center gap-2">
            {/* Operation filter */}
            <select
              value={selectedFilter}
              onChange={(e) => setSelectedFilter(e.target.value)}
              className="h-7 px-2 text-[11px] bg-white border border-[#bdc7ba] rounded-sm text-[#111813] font-mono focus:outline-none focus:border-[#1a5935]"
            >
              <option value="ALL">All Operations (Excl. HMAC)</option>
              {Object.keys(OPERATION_LABELS).map((opKey) => (
                <option key={opKey} value={opKey}>
                  {OPERATION_LABELS[opKey]?.label || opKey}
                </option>
              ))}
            </select>

            {/* Payload size tier filter */}
            <select
              value={selectedSizeTier}
              onChange={(e) => setSelectedSizeTier(e.target.value)}
              className="h-7 px-2 text-[11px] bg-white border border-[#bdc7ba] rounded-sm text-[#111813] font-mono focus:outline-none focus:border-[#1a5935]"
            >
              {SIZE_TIERS.map((tier) => (
                <option key={tier.id} value={tier.id}>
                  {tier.label}
                </option>
              ))}
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
                      <p className="text-sm font-semibold text-[#111813]">No Benchmark Telemetry Matching Filters</p>
                      <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                        No recorded telemetry matches the selected operation or payload size filters. Ingesting artifacts, verifying digital signatures, or running PCAP packet dissections will automatically record high-resolution empirical timer measurements here.
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                benchmarks.map((b) => (
                  <tr key={b.id} className="hover:bg-[#faf8f3] transition-colors">
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span
                        className="font-mono text-[11px] font-bold px-1.5 py-0.5 rounded-sm border"
                        style={{
                          backgroundColor: `${OPERATION_LABELS[b.benchmark_name]?.color || '#1a5935'}15`,
                          color: OPERATION_LABELS[b.benchmark_name]?.color || '#111813',
                          borderColor: `${OPERATION_LABELS[b.benchmark_name]?.color || '#1a5935'}40`,
                        }}
                      >
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

      {/* Forensic Rigor Methodology & Hardware Context */}
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
        <Card title="Contextual Variance Notice">
          <p className="text-[#536050] leading-relaxed">
            Execution durations depend directly on payload size, CPU architecture, memory bandwidth, and system load. Operations perform distinct cryptographic tasks and are not directly equivalent.
          </p>
        </Card>
      </div>
    </div>
  );
}
