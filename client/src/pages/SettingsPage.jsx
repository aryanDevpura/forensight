import React from 'react';
import { Card } from '../components/common/Card';

export function SettingsPage({ healthData }) {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Card
          title="Investigation Server Configuration"
          subtitle="Runtime variables loaded from server environment (.env)"
        >
          <div className="divide-y divide-[#eaede8] text-xs">
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Listen Host:</span>
              <span className="font-mono text-[#111813]">127.0.0.1</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Listen Port:</span>
              <span className="font-mono text-[#111813]">8000</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Environment:</span>
              <span className="font-mono text-[#111813]">{healthData?.environment || 'development'}</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Database ORM:</span>
              <span className="text-[#111813]">SQLAlchemy 2.0 / SQLite 3</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Database URI:</span>
              <span className="font-mono text-[#111813]">sqlite:///./forensight.db</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Allowed CORS Origins:</span>
              <span className="font-mono text-[11px] text-[#111813]">http://localhost:5173, http://127.0.0.1:5173</span>
            </div>
          </div>
        </Card>

        <Card
          title="Secure Ingestion & Cryptography"
          subtitle="Unified digital evidence security topology and cryptographic parameters"
        >
          <div className="divide-y divide-[#eaede8] text-xs">
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Ingestion Endpoint:</span>
              <span className="font-mono text-[#111813] font-semibold">POST /api/evidence</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Digital Signature:</span>
              <span className="font-mono text-[11px] text-[#0369a1] font-semibold">RSA-PSS / SHA-256 (32-byte salt)</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Key Wrapping:</span>
              <span className="font-mono text-[11px] text-[#0369a1] font-semibold">RSA-OAEP / SHA-256 (2048-bit KEK)</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Transfer & Rest Encryption:</span>
              <span className="font-mono text-[11px] text-[#1a5935] font-semibold">AES-256-GCM (96-bit random nonce)</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Trusted Signers Store:</span>
              <span className="font-mono text-[11px] text-[#111813]">server/keys/trusted_signers/</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Server Public Key:</span>
              <span className="font-mono text-[11px] text-[#1a5935]">
                {import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api/system/public-keys` : '/api/system/public-keys'}
              </span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Integrity Standard:</span>
              <span className="text-[#111813] font-mono text-[11px]">Original Plaintext SHA-256 Digest</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Storage Security:</span>
              <span className="font-mono text-[11px] text-[#1a5935] font-semibold">At-Rest Authenticated Ciphertext</span>
            </div>
          </div>
        </Card>
      </div>

      <Card
        title="Local Storage Subsystem"
        subtitle="Filesystem directories allocated for evidence isolation and case reporting"
      >
        <div className="divide-y divide-[#eaede8] text-xs">
          <div className="flex flex-col sm:flex-row sm:justify-between py-2 gap-1">
            <span className="text-[#536050]">Evidence Intake Path:</span>
            <span className="font-mono text-[#111813] break-all">{healthData?.storage?.evidence_path || 'server/storage/evidence'}</span>
          </div>
          <div className="flex flex-col sm:flex-row sm:justify-between py-2 gap-1">
            <span className="text-[#536050]">Case Reports Path:</span>
            <span className="font-mono text-[#111813] break-all">{healthData?.storage?.reports_path || 'server/storage/reports'}</span>
          </div>
        </div>
      </Card>
    </div>
  );
}
