import React from 'react';
import {
  LayoutDashboard,
  HardDrive,
  Activity,
  History,
  Link as LinkIcon,
  Cpu,
  FileText,
  Sliders,
  Shield,
} from 'lucide-react';

const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'evidence', label: 'Evidence', icon: HardDrive },
  { id: 'analysis', label: 'Analysis', icon: Activity },
  { id: 'timeline', label: 'Timeline', icon: History },
  { id: 'custody', label: 'Chain of Custody', icon: LinkIcon },
  { id: 'performance', label: 'Performance', icon: Cpu },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'settings', label: 'Settings', icon: Sliders },
];

export function Sidebar({ currentTab, onSelectTab, isServerOnline }) {
  return (
    <aside className="w-64 bg-[#112117] border-r border-[#1d3324] flex flex-col shrink-0 select-none text-[#faf8f3]">
      {/* Brand & System Identifier */}
      <div className="p-4 border-b border-[#1d3324]">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-sm bg-[#183121] border border-[#23452f] flex items-center justify-center text-[#faf8f3]">
            <Shield className="w-4 h-4 text-[#8ec89f]" />
          </div>
          <div>
            <h1 className="font-bold text-[#faf8f3] text-sm tracking-wide">
              FORENSIGHT
            </h1>
            <p className="text-[10px] text-[#9cb1a2] font-mono tracking-tight uppercase">
              Digital Evidence & Forensics
            </p>
          </div>
        </div>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 px-2.5 py-4 space-y-1">
        <div className="px-3 pb-2 text-[10px] font-mono uppercase tracking-wider text-[#799080] font-semibold">
          Investigation Modules
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center gap-3 px-3 py-2 text-xs font-medium rounded-sm transition-colors text-left ${
                isActive
                  ? 'bg-[#1b5e34] text-white border border-[#2e7d4a] font-semibold'
                  : 'text-[#bdc7ba] hover:text-[#faf8f3] hover:bg-[#162c1e] border border-transparent'
              }`}
            >
              <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-white' : 'text-[#8da090]'}`} />
              <span className="font-sans">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Footer System Node Info */}
      <div className="p-3.5 border-t border-[#1d3324] bg-[#0c1810] text-[11px] text-[#9cb1a2]">
        <div className="flex items-center justify-between font-mono">
          <span className="text-[#799080]">SERVER LINK</span>
          <span className="inline-flex items-center gap-1.5 font-medium">
            <span
              className={`h-2 w-2 rounded-full ${
                isServerOnline ? 'bg-[#22c55e]' : 'bg-[#dc2626]'
              }`}
            />
            <span className={isServerOnline ? 'text-[#86efac]' : 'text-[#fca5a5]'}>
              {isServerOnline ? 'CONNECTED' : 'DISCONNECTED'}
            </span>
          </span>
        </div>
        <div className="mt-1 font-mono text-[10px] text-[#799080] truncate">
          v0.1.0 • Standalone Node
        </div>
      </div>
    </aside>
  );
}
