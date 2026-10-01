import React from 'react';

export default function PageHeader({ title, description, actions, badge }) {
  return (
    <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 mb-6 border-b border-slate-800/80 gap-4">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">{title}</h1>
          {badge}
        </div>
        {description && <p className="text-sm text-slate-400 mt-1 max-w-3xl">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-3 shrink-0">{actions}</div>}
    </div>
  );
}
