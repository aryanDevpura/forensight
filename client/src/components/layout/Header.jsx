import React from 'react';
import { RefreshCw, Server, Database } from 'lucide-react';
import { StatusBadge } from '../common/StatusBadge';

export function Header({
  title,
  subtitle,
  healthData,
  isRefreshing,
  onRefresh,
  lastChecked,
}) {
  return (
    <header className="h-14 bg-white border-b border-[#d7ded4] px-6 flex items-center justify-between shrink-0">
      <div>
        <h2 className="text-sm font-bold text-[#111813] uppercase tracking-wide font-sans">
          {title}
        </h2>
        {subtitle && <p className="text-[11px] text-[#536050] font-normal font-sans">{subtitle}</p>}
      </div>

      <div className="flex items-center gap-3">
        {/* Backend & DB status overview */}
        <div className="hidden md:flex items-center gap-3 text-xs border border-[#d7ded4] bg-[#fbfaf7] px-2.5 py-1 rounded-sm">
          <div className="flex items-center gap-1.5 text-[#3e483c] font-sans">
            <Server className="w-3.5 h-3.5 text-[#6c7a68]" />
            <span className="text-[11px] font-medium text-[#536050]">API:</span>
            <StatusBadge
              status={healthData ? healthData.status : 'offline'}
              label={healthData ? 'ONLINE' : 'UNREACHABLE'}
              size="xs"
            />
          </div>

          <div className="h-3 w-px bg-[#d7ded4]" />

          <div className="flex items-center gap-1.5 text-[#3e483c] font-sans">
            <Database className="w-3.5 h-3.5 text-[#6c7a68]" />
            <span className="text-[11px] font-medium text-[#536050]">DB:</span>
            <StatusBadge
              status={healthData ? healthData.database : 'disconnected'}
              label={healthData?.database === 'connected' ? 'SQLITE READY' : 'NO DB'}
              size="xs"
            />
          </div>
        </div>

        {/* Manual re-check trigger */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          title="Refresh server health and stats"
          className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-[#f4f1ea] hover:bg-[#eaede8] disabled:opacity-50 text-[#111813] text-xs font-sans rounded-sm border border-[#bdc7ba] transition-colors"
        >
          <RefreshCw className={`w-3 h-3 text-[#536050] ${isRefreshing ? 'animate-spin' : ''}`} />
          <span className="font-medium text-[11px]">{isRefreshing ? 'Checking...' : 'Check Status'}</span>
        </button>
      </div>
    </header>
  );
}
