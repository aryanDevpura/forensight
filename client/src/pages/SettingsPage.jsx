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
          title="Collector Node Topology"
          subtitle="Agent configuration for remote and local evidence transmission"
        >
          <div className="divide-y divide-[#eaede8] text-xs">
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Collector ID:</span>
              <span className="font-mono text-[#111813] font-semibold">collector-node-01</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Target Server Host:</span>
              <span className="font-mono text-[#111813]">127.0.0.1 (Configurable via .env)</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Target Server Port:</span>
              <span className="font-mono text-[#111813]">8000</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Collector Module:</span>
              <span className="font-mono text-[11px] text-[#111813]">collector/collector.py</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Server Probe Target:</span>
              <span className="font-mono text-[11px] text-[#1a5935]">http://127.0.0.1:8000/api/health</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Telemetry Protocol:</span>
              <span className="text-[#111813]">REST / JSON HTTP</span>
            </div>
            <div className="flex justify-between py-2">
              <span className="text-[#536050]">Transfer Encryption:</span>
              <span className="font-mono text-[11px] text-[#1a5935] font-semibold">AES-256-GCM (Authenticated)</span>
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
