import React from 'react';
import { Card } from '../components/common/Card';
import { FileText } from 'lucide-react';

export function ReportsPage() {
  return (
    <div className="space-y-5">
      <Card
        title="Forensic Investigation Reports"
        subtitle="Repository of generated case dossiers and court-admissible integrity reports"
        action={
          <div className="text-[11px] font-mono text-[#536050] bg-[#faf8f3] px-2 py-0.5 border border-[#d7ded4] rounded-sm">
            Target Directory: server/storage/reports
          </div>
        }
      >
        <div className="border border-[#d7ded4] rounded-sm overflow-hidden bg-white">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#faf8f3] text-[#3e483c] border-b border-[#d7ded4]">
              <tr>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Report ID</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Case Title</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Export Format</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Evidence Items</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Integrity Seal</th>
                <th className="py-2.5 px-3 font-semibold text-[11px] uppercase tracking-wider">Generated (UTC)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#eaede8] bg-white">
              <tr>
                <td colSpan={6} className="py-14 text-center text-[#536050]">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <FileText className="w-7 h-7 text-[#94a190]" />
                    <p className="text-sm font-semibold text-[#111813]">0 Case Reports Generated</p>
                    <p className="text-xs text-[#536050] max-w-lg leading-relaxed">
                      The reports repository is currently empty. Automated case report generation combining Chain of Custody records, SHA-256 hashes, and packet inspection findings will be implemented in Milestone 4.
                    </p>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-xs">
        <Card title="Report Export Standards">
          <ul className="space-y-2 text-[#3e483c]">
            <li className="flex items-start gap-2">
              <span className="font-mono text-[#536050]">•</span>
              <span><strong>Admissible PDF Dossier:</strong> Formal forensic layout detailing examiner identity, evidence ledger, timeline, and cryptographic signatures</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="font-mono text-[#536050]">•</span>
              <span><strong>Machine-Readable JSON Manifest:</strong> Structured schema including evidence hashes, packet flow statistics, and raw finding timestamps</span>
            </li>
          </ul>
        </Card>

        <Card title="Integrity Seal Architecture">
          <p className="text-[#536050] leading-relaxed">
            Every exported report will be cryptographically signed with the investigation server's private key, generating an accompanying detached signature file to prevent subsequent tampering.
          </p>
        </Card>
      </div>
    </div>
  );
}
