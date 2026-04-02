import { type ReactNode } from 'react';
import { Sidebar } from './Sidebar';

interface PageShellProps {
  children: ReactNode;
}

export function PageShell({ children }: PageShellProps) {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 ml-56 p-6">
        {children}
      </main>
    </div>
  );
}
