import React from 'react';

export default function Card({ children, className = '', title, subtitle, action, glow = false }) {
  return (
    <div
      className={`glass-panel rounded-xl p-6 relative overflow-hidden transition-all duration-300 ${
        glow ? 'border-cyan-500/30 shadow-cyber-glow' : 'border-slate-800/80 shadow-cyber-card'
      } ${className}`}
    >
      {(title || subtitle || action) && (
        <div className="flex items-start justify-between mb-4 border-b border-slate-800/60 pb-3">
          <div>
            {title && <h3 className="text-base font-semibold text-slate-100 tracking-tight">{title}</h3>}
            {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      {children}
    </div>
  );
}
