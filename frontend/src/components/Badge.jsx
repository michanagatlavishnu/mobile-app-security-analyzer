import React from 'react';
import { getSeverityColor } from '../utils/formatters';

export default function Badge({ label, severity, variant = 'default', size = 'sm', className = '' }) {
  if (severity) {
    const colors = getSeverityColor(severity);
    return (
      <span
        className={`inline-flex items-center font-mono font-medium rounded-md border ${colors.bg} ${colors.text} ${colors.border} ${
          size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-sm'
        } ${className}`}
      >
        <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${colors.dot}`}></span>
        {label || severity}
      </span>
    );
  }

  const variants = {
    default: 'bg-slate-800 text-slate-300 border-slate-700',
    primary: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    success: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    warning: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    danger: 'bg-red-500/10 text-red-400 border-red-500/30',
  };

  return (
    <span
      className={`inline-flex items-center font-medium rounded-md border ${variants[variant] || variants.default} ${
        size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-sm'
      } ${className}`}
    >
      {label}
    </span>
  );
}
