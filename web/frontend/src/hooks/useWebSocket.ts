import { useCallback, useEffect, useRef, useState } from 'react';

export interface LogLine {
  type: 'log' | 'close' | 'ping';
  line?: string;
  run_id?: string;
}

export function useWebSocket(runId: string | null) {
  const [lines, setLines] = useState<string[]>([]);
  const [connected, setConnected] = useState(false);
  const [done, setDone] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!runId) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/logs/${runId}`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      setDone(true);
    };
    ws.onmessage = (event) => {
      try {
        const data: LogLine = JSON.parse(event.data);
        if (data.type === 'log' && data.line !== undefined) {
          setLines((prev) => [...prev, data.line!]);
        } else if (data.type === 'close') {
          setDone(true);
        }
      } catch {
        // ignore malformed messages
      }
    };
    ws.onerror = () => setConnected(false);

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [runId]);

  const clear = useCallback(() => setLines([]), []);

  return { lines, connected, done, clear };
}
