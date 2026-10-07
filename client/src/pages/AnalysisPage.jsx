import React from 'react';
import { Card } from '../components/common/Card';
import { Activity } from 'lucide-react';

export function AnalysisPage() {
  return (
    <div className="space-y-5">
      <Card
        title="Forensic Findings & Alert Registry"
        subtitle="Threat alerts and anomalies detected from PCAP packet captures and host artifacts"
        action={
          <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
            Engine: PyShark / Heuristics (Standby)
          </div>
        }
      >
        <div className="border border-[#d7ded4] rounded-sm overflow-hidden bg-white">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
              <tr>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Finding ID</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Evidence Ref</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Threat Category</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Severity</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Description</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Detection Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#eaede8] bg-white">
              <tr>
                <td colSpan={6} className="py-14 text-center text-[#536050]">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <Activity className="w-7 h-7 text-[#94a190]" />
                    <p className="text-sm font-semibold text-[#111813]">No Forensic Findings</p>
                    <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                      Analysis pipeline is idle. Packet inspection, port-scan heuristics, beaconing analysis, and USB event correlation will be activated in Milestone 3 once evidence files are acquired.
                    </p>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5 text-xs">
        <Card title="PCAP Deep Inspection">
          <p className="text-[#536050] leading-relaxed">
            PyShark/TShark engine will parse network captures to reconstruct TCP/UDP streams, DNS queries, and TLS client hello metadata.
          </p>
        </Card>
        <Card title="Heuristic Anomaly Detection">
          <p className="text-[#536050] leading-relaxed">
            Automated statistical checks for horizontal/vertical reconnaissance scans and cyclical C2 beaconing intervals.
          </p>
        </Card>
        <Card title="Correlated Timeline">
          <p className="text-[#536050] leading-relaxed">
            Network findings will be temporally correlated with local file system modifications and peripheral hardware connection events.
          </p>
        </Card>
      </div>
    </div>
  );
}
