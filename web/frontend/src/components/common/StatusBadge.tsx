interface StatusBadgeProps {
  status: string;
}

const colors: Record<string, string> = {
  complete: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  generating: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  scanning: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  analyzing: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  pending: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
  failed: 'bg-red-500/20 text-red-400 border-red-500/30',
  cancelled: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  running: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

export function StatusBadge({ status }: StatusBadgeProps) {
  const cls = colors[status] || colors.pending;
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${cls}`}>
      {status === 'generating' || status === 'scanning' || status === 'analyzing' ? (
        <span className="mr-1.5 h-1.5 w-1.5 rounded-full bg-current animate-pulse" />
      ) : null}
      {status}
    </span>
  );
}
