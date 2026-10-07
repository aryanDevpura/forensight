import React from 'react';
import { Card } from '../components/common/Card';
import { Gauge, Activity } from 'lucide-react';

export function PerformancePage() {
  return (
    <div className="space-y-5">
      <Card
        title="Forensic Performance Benchmarking"
        subtitle="Throughput and execution latency measurements for hashing, transmission, and parsing"
        action={
          <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
            Status: Standby for Execution
          </div>
        }
      >
        <div className="border border-[#d7ded4] rounded-sm overflow-hidden bg-white">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
              <tr>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Benchmark Suite</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Test Sample Size</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Execution Latency</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Throughput</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Hardware Profile</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Execution Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#eaede8] bg-white">
              <tr>
                <td colSpan={6} className="py-14 text-center text-[#536050]">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <Gauge className="w-7 h-7 text-[#94a190]" />
                    <p className="text-sm font-semibold text-[#111813]">No Benchmark Runs Recorded</p>
                    <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                      Benchmark suite is uninitialized. Automated timing benchmarks for SHA-256 hashing, HMAC operations, and network transfer rates will populate here upon execution in Milestone 4.
                    </p>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </Card>

      {/* Empty Chart Container structure without fake charts */}
      <Card
        title="Throughput Telemetry Visualizer"
        subtitle="Time-series chart container for real benchmark telemetry runs"
      >
        <div className="border border-dashed border-[#d7ded4] bg-[#faf8f3] rounded-sm p-8 text-center">
          <Activity className="w-6 h-6 text-[#94a190] mx-auto mb-2" />
          <div className="text-xs font-semibold text-[#111813]">Awaiting Benchmark Telemetry Data</div>
          <div className="text-[11px] text-[#536050] mt-0.5 max-w-md mx-auto">
            Real data points will be plotted here after benchmarking rounds are run against real payload samples. No simulated data is displayed.
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
        <Card title="Planned Performance Evaluations">
          <ul className="space-y-2 text-[#3e483c]">
            <li className="flex items-start gap-2">
              <span className="font-mono text-[#536050]">•</span>
              <span><strong>Cryptographic Digest Speed:</strong> SHA-256 chunked calculation throughput across 10MB to 1GB test artifacts</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="font-mono text-[#536050]">•</span>
              <span><strong>Transport Overhead:</strong> Loopback vs remote node transmission latency and bandwidth saturation</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="font-mono text-[#536050]">•</span>
              <span><strong>Dissection Rate:</strong> Packets parsed per second by PyShark under high packet-density captures</span>
            </li>
          </ul>
        </Card>

        <Card title="Measurement Rigor">
          <p className="text-[#536050] leading-relaxed">
            All benchmarks will capture CPU execution time, wall-clock duration, memory delta, and host platform hardware attributes to satisfy empirical forensic research requirements.
          </p>
        </Card>
      </div>
    </div>
  );
}
