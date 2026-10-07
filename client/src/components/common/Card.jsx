import React from 'react';

export function Card({ title, subtitle, action, children, className = '' }) {
  return (
    <div className={`bg-white border border-[#d7ded4] rounded-sm p-4 sm:p-5 shadow-none ${className}`}>
      {(title || subtitle || action) && (
        <div className="flex items-start justify-between mb-4 pb-3 border-b border-[#eaede8]">
          <div>
            {title && (
              <h3 className="text-xs font-bold text-[#111813] uppercase tracking-wider font-sans">
                {title}
              </h3>
            )}
            {subtitle && (
              <p className="text-xs text-[#536050] mt-0.5 font-sans">
                {subtitle}
              </p>
            )}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      {children}
    </div>
  );
}
