import React from 'react';
import { Card } from '../components/common/Card';
import { StatusBadge } from '../components/common/StatusBadge';
import { Server, Database, FolderCheck, HardDrive, AlertTriangle } from 'lucide-react';

export function DashboardPage({ healthData, statsData, error, isLoading }) {
  const isHealthy = healthData && healthData.status === 'ok';

  return (
    <div className="space-y-5">
      {/* System Warning if backend is unreachable */}
      {error && (
        <div className="p-3.5 bg-[#fee2e2] border border-[#ef4444] rounded-sm text-[#991b1b] text-xs flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 shrink-0 text-[#991b1b] mt-0.5" />
          <div>
            <div className="font-bold text-[#7f1d1d]">Backend Communication Failure</div>
            <div className="text-[#991b1b] mt-0.5">{error}</div>
            <div className="text-[#7f1d1d] mt-1 font-mono text-[11px]">
              Unable to reach FastAPI server. Verify the Investigation Server is running and accessible via Vite proxy (check VITE_PROXY_TARGET in client/.env.local).
            </div>
          </div>
        </div>
      )}

      {/* Primary Health & Node Status Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {/* Backend Server Status */}
        <div className="bg-white border border-[#d7ded4] rounded-sm p-3.5">
          <div className="flex items-center justify-between text-xs text-[#536050] mb-1.5">
            <span className="flex items-center gap-1.5 font-medium">
              <Server className="w-3.5 h-3.5 text-[#6c7a68]" />
              API SERVER
            </span>
            <StatusBadge status={isHealthy ? 'ok' : 'error'} label={isHealthy ? 'RUNNING' : 'OFFLINE'} size="xs" />
          </div>
          <div className="text-sm font-bold text-[#111813]">
            {healthData ? healthData.app : 'FastAPI Backend'}
          </div>
          <div className="text-[11px] text-[#536050] font-sans mt-0.5">
            Version <span className="font-mono text-[11px] font-semibold text-[#111813]">{healthData ? healthData.version : '0.1.0'}</span> • {healthData ? healthData.environment : 'N/A'}
          </div>
        </div>

        {/* Database Status */}
        <div className="bg-white border border-[#d7ded4] rounded-sm p-3.5">
          <div className="flex items-center justify-between text-xs text-[#536050] mb-1.5">
            <span className="flex items-center gap-1.5 font-medium">
              <Database className="w-3.5 h-3.5 text-[#6c7a68]" />
              DATABASE
            </span>
            <StatusBadge
              status={healthData?.database === 'connected' ? 'connected' : 'error'}
              label={healthData?.database === 'connected' ? 'CONNECTED' : 'DISCONNECTED'}
              size="xs"
            />
          </div>
          <div className="text-sm font-bold text-[#111813]">
            SQLite 3 (Local)
          </div>
          <div className="text-[11px] text-[#536050] font-sans mt-0.5">
            File: <span className="font-mono text-[11px]">forensight.db</span>
          </div>
        </div>

        {/* Evidence Storage Directory */}
        <div className="bg-white border border-[#d7ded4] rounded-sm p-3.5">
          <div className="flex items-center justify-between text-xs text-[#536050] mb-1.5">
            <span className="flex items-center gap-1.5 font-medium">
              <HardDrive className="w-3.5 h-3.5 text-[#6c7a68]" />
              EVIDENCE STORE
            </span>
            <StatusBadge
              status={healthData?.storage?.evidence_dir === 'available' ? 'available' : 'error'}
              label={healthData?.storage?.evidence_dir === 'available' ? 'VERIFIED' : 'UNAVAILABLE'}
              size="xs"
            />
          </div>
          <div className="text-sm font-bold text-[#111813]">
            Evidence Directory
          </div>
          <div className="text-[11px] text-[#536050] font-mono mt-0.5 truncate" title={healthData?.storage?.evidence_path}>
            server/storage/evidence
          </div>
        </div>

        {/* Reports Storage Directory */}
        <div className="bg-white border border-[#d7ded4] rounded-sm p-3.5">
          <div className="flex items-center justify-between text-xs text-[#536050] mb-1.5">
            <span className="flex items-center gap-1.5 font-medium">
              <FolderCheck className="w-3.5 h-3.5 text-[#6c7a68]" />
              REPORTS STORE
            </span>
            <StatusBadge
              status={healthData?.storage?.reports_dir === 'available' ? 'available' : 'error'}
              label={healthData?.storage?.reports_dir === 'available' ? 'VERIFIED' : 'UNAVAILABLE'}
              size="xs"
            />
          </div>
          <div className="text-sm font-bold text-[#111813]">
            Case Reports Repository
          </div>
          <div className="text-[11px] text-[#536050] font-mono mt-0.5 truncate" title={healthData?.storage?.reports_path}>
            server/storage/reports
          </div>
        </div>
      </div>

      {/* Investigation Database Telemetry (Live actual 0 counts) */}
      <Card
        title="Investigation Database Metrics"
        subtitle="Genuine record counts from local SQLite database (Zero synthetic or simulated data)"
      >
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          <div className="border border-[#d7ded4] bg-[#faf8f3] p-3 rounded-sm">
            <div className="text-[11px] font-sans font-semibold text-[#536050] uppercase tracking-wide">Evidence Items</div>
            <div className="text-2xl font-bold font-mono text-[#111813] mt-1">
              {statsData ? statsData.evidence_count : 0}
            </div>
            <div className="text-[11px] text-[#6c7a68] mt-0.5">
              {statsData?.evidence_count === 1 ? '1 file registered' : `${statsData ? statsData.evidence_count : 0} files registered`}
            </div>
          </div>

          <div className="border border-[#d7ded4] bg-[#faf8f3] p-3 rounded-sm">
            <div className="text-[11px] font-sans font-semibold text-[#536050] uppercase tracking-wide">Findings Logged</div>
            <div className="text-2xl font-bold font-mono text-[#111813] mt-1">
              {statsData ? statsData.findings_count : 0}
            </div>
            <div className="text-[11px] text-[#6c7a68] mt-0.5">Awaiting analysis run</div>
          </div>

          <div className="border border-[#d7ded4] bg-[#faf8f3] p-3 rounded-sm">
            <div className="text-[11px] font-sans font-semibold text-[#536050] uppercase tracking-wide">Audit Events</div>
            <div className="text-2xl font-bold font-mono text-[#111813] mt-1">
              {statsData ? statsData.events_count : 0}
            </div>
            <div className="text-[11px] text-[#6c7a68] mt-0.5">Timeline clear</div>
          </div>

          <div className="border border-[#d7ded4] bg-[#faf8f3] p-3 rounded-sm">
            <div className="text-[11px] font-sans font-semibold text-[#536050] uppercase tracking-wide">Custody Entries</div>
            <div className="text-2xl font-bold font-mono text-[#111813] mt-1">
              {statsData ? statsData.custody_records_count : 0}
            </div>
            <div className="text-[11px] text-[#6c7a68] mt-0.5">0 transfers logged</div>
          </div>

          <div className="border border-[#d7ded4] bg-[#faf8f3] p-3 rounded-sm">
            <div className="text-[11px] font-sans font-semibold text-[#536050] uppercase tracking-wide">Benchmarks</div>
            <div className="text-2xl font-bold font-mono text-[#111813] mt-1">
              {statsData ? statsData.benchmark_runs_count : 0}
            </div>
            <div className="text-[11px] text-[#6c7a68] mt-0.5">0 runs executed</div>
          </div>
        </div>
      </Card>

      {/* Collector Node Configuration & Forensic Modules Roadmap */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Card
          title="Evidence Collector Configuration"
          subtitle="Collector node parameters for local or remote evidence transmission"
        >
          <div className="divide-y divide-[#eaede8] text-xs">
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Collector Node ID:</span>
              <span className="font-mono text-[#111813] font-semibold">collector-node-01</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Configured Target Host:</span>
              <span className="font-mono text-[#111813]">Configurable (.env / Remote Host)</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Default Target Port:</span>
              <span className="font-mono text-[#111813]">8000</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Network Topology:</span>
              <span className="text-[#1a5935] font-medium">Windows Collector → Ubuntu FastAPI Server</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Collector Status:</span>
              <span className="text-[#536050] font-medium">{statsData?.collector_status || 'Configured (Standby)'}</span>
            </div>
          </div>
        </Card>

        <Card
          title="Forensic Security & Pipeline Capabilities"
          subtitle="Cryptographic integrity and analysis mechanisms supported by the platform"
        >
          <div className="divide-y divide-[#eaede8] text-xs">
            <div className="flex items-center justify-between py-2">
              <span className="text-[#111813] font-medium">FastAPI Server & SQLite Storage</span>
              <StatusBadge status={isHealthy ? 'ok' : 'standby'} label={isHealthy ? 'ONLINE' : 'STANDBY'} size="xs" />
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-[#111813] font-medium">HMAC-SHA256 Collector Authentication</span>
              <span className="px-1.5 py-0.5 rounded-sm bg-[#faf8f3] text-[#1b5e34] border border-[#d7ded4] font-mono text-[10px] font-semibold">
                CONFIGURED
              </span>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-[#111813] font-medium">AES-256-GCM Transfer Encryption</span>
              <span className="px-1.5 py-0.5 rounded-sm bg-[#faf8f3] text-[#1b5e34] border border-[#d7ded4] font-mono text-[10px] font-semibold">
                SUPPORTED
              </span>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-[#111813] font-medium">SHA-256 Payload Integrity Verification</span>
              <span className="px-1.5 py-0.5 rounded-sm bg-[#faf8f3] text-[#1b5e34] border border-[#d7ded4] font-mono text-[10px] font-semibold">
                ENFORCED ON UPLOAD
              </span>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-[#111813] font-medium">Forensic Timeline & Correlation Engine</span>
              <span className="px-1.5 py-0.5 rounded-sm bg-[#faf8f3] text-[#111813] border border-[#d7ded4] font-mono text-[10px] font-semibold">
                READY
              </span>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-[#111813] font-medium">Monotonic Benchmark Instrumentation</span>
              <span className="px-1.5 py-0.5 rounded-sm bg-[#faf8f3] text-[#111813] border border-[#d7ded4] font-mono text-[10px] font-semibold">
                {statsData?.benchmark_runs_count ? `${statsData.benchmark_runs_count} RUNS RECORDED` : 'READY'}
              </span>
            </div>
          </div>
        </Card>
      </div>

      {/* Investigation Server Telemetry Trace */}
      <Card
        title="Server Health Telemetry Trace"
        subtitle="Raw JSON payload received from GET /api/health"
      >
        <pre className="bg-[#faf8f3] border border-[#d7ded4] rounded-sm p-3.5 text-[11px] font-mono text-[#111813] overflow-x-auto">
          {healthData ? JSON.stringify(healthData, null, 2) : 'Awaiting server response...'}
        </pre>
      </Card>
    </div>
  );
}
