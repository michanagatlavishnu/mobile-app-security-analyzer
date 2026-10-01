import React from 'react';

export default function LoadingSpinner({ size = 'md', message = 'Loading security data...' }) {
  const sizeClasses = {
    sm: 'h-5 w-5',
    md: 'h-8 w-8',
    lg: 'h-12 w-12',
  };

  return (
    <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
      <div className="relative">
        <div className={`${sizeClasses[size] || sizeClasses.md} rounded-full border-2 border-slate-800 border-t-cyan-500 animate-spin`} />
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
        </div>
      </div>
      {message && <p className="mt-4 text-xs font-mono text-slate-400 tracking-wide">{message}</p>}
    </div>
  );
}
