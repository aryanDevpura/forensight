import React from 'react';
import { Card } from '../components/common/Card';
import { History } from 'lucide-react';

export function TimelinePage() {
  return (
    <div className="space-y-5">
      <Card
        title="Forensic Event Timeline"
        subtitle="Chronological audit log of acquisition triggers, network transmissions, and analysis operations"
        action={
          <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
            UTC Synchronized
          </div>
        }
      >
        <div className="border border-[#d7ded4] rounded-sm overflow-hidden bg-white">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
              <tr>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Event ID</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Timestamp (UTC)</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Source Entity</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Severity</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Audit Message</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#eaede8] bg-white">
              <tr>
                <td colSpan={5} className="py-14 text-center text-[#536050]">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <History className="w-7 h-7 text-[#94a190]" />
                    <p className="text-sm font-semibold text-[#111813]">Investigation Timeline Empty</p>
                    <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                      Zero event records logged in the database. Operational checkpoints, collector handshakes, and examiner investigations will generate immutable timestamped records here.
                    </p>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
