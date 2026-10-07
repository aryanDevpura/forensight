import React from 'react';
import { Card } from '../components/common/Card';
import { Link as LinkIcon } from 'lucide-react';

export function CustodyPage() {
  return (
    <div className="space-y-5">
      <Card
        title="Chain of Custody Ledger"
        subtitle="Immutable audit log verifying artifact integrity across transfer and examination stages"
        action={
          <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
            Admissibility Standard: Federal Rules of Evidence Rule 901
          </div>
        }
      >
        <div className="border border-[#d7ded4] rounded-sm overflow-hidden bg-white">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
              <tr>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Evidence ID</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Actor / Handler</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Device / Host</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Custody Action</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Timestamp (UTC)</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Verification Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#eaede8] bg-white">
              <tr>
                <td colSpan={6} className="py-14 text-center text-[#536050]">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <LinkIcon className="w-7 h-7 text-[#94a190]" />
                    <p className="text-sm font-semibold text-[#111813]">0 Chain of Custody Records</p>
                    <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                      The chain of custody ledger is empty. Evidence intake, collector transfers, cryptographic checksum verifications, and examiner checkouts will record tamper-evident entries here.
                    </p>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </Card>

      <div className="bg-white border border-[#d7ded4] rounded-sm p-4 text-xs">
        <h4 className="font-bold text-[#111813] uppercase tracking-wider text-[11px] mb-1">
          Evidence Admissibility Protocol
        </h4>
        <p className="text-[#536050] leading-relaxed">
          The chain of custody subsystem documents every entity that accessed or transferred digital evidence from the instant of acquisition. Each transaction links previous hashes to ensure any retroactive alteration is immediately detectable.
        </p>
      </div>
    </div>
  );
}
