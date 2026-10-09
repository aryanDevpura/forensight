import React from 'react';

export function StatusBadge({ status, label, size = 'sm' }) {
  const normalized = (status || '').toLowerCase();

  let dotColor = 'bg-[#6c7a68]';
  let badgeStyle = 'bg-[#eaede8] text-[#3e483c] border-[#bdc7ba]';

  if (
    normalized === 'ok' ||
    normalized === 'connected' ||
    normalized === 'operational' ||
    normalized === 'available' ||
    normalized === 'running' ||
    normalized === 'verified' ||
    normalized === 'intact'
  ) {
    dotColor = 'bg-[#1a5935]';
    badgeStyle = 'bg-[#f0f9f3] text-[#144629] border-[#227244]/40';
  } else if (
    normalized === 'warning' ||
    normalized === 'standby' ||
    normalized === 'partial' ||
    normalized === 'pending'
  ) {
    dotColor = 'bg-[#b45309]';
    badgeStyle = 'bg-[#fef3c7] text-[#92400e] border-[#f59e0b]/50';
  } else if (
    normalized === 'error' ||
    normalized === 'offline' ||
    normalized === 'disconnected' ||
    normalized === 'missing' ||
    normalized === 'file_missing' ||
    normalized === 'tampered' ||
    normalized === 'critical'
  ) {
    dotColor = 'bg-[#991b1b]';
    badgeStyle = 'bg-[#fee2e2] text-[#991b1b] border-[#ef4444]/50';
  }

  const padding = size === 'xs' ? 'px-1.5 py-0.5 text-[11px]' : 'px-2 py-0.5 text-xs';

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-sm font-sans font-medium border ${badgeStyle} ${padding}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${dotColor}`} />
      <span className="font-mono text-[11px] uppercase tracking-wide">{label || status}</span>
    </span>
  );
}
