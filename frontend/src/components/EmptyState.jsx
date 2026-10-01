import React from 'react';
import { ShieldAlert } from 'lucide-react';
import Button from './Button';

export default function EmptyState({
  title = 'No Records Found',
  description = 'No security findings or scan history available at this time.',
  icon: Icon = ShieldAlert,
  actionLabel,
  onAction,
}) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center rounded-xl border border-dashed border-slate-800 bg-slate-950/40">
      <div className="flex h-14 w-14 items-center justify-center rounded-full bg-slate-900 border border-slate-800 text-slate-400 mb-4">
        <Icon className="h-7 w-7 text-cyan-500/80" />
      </div>
      <h3 className="text-base font-semibold text-slate-200">{title}</h3>
      <p className="mt-1 text-sm text-slate-400 max-w-sm">{description}</p>
      {actionLabel && onAction && (
        <div className="mt-6">
          <Button variant="primary" size="sm" onClick={onAction}>
            {actionLabel}
          </Button>
        </div>
      )}
    </div>
  );
}
