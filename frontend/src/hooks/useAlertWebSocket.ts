import { useEffect, useRef, useState, useCallback } from 'react';
import type { Alert } from '../types/alert';

export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected';

const RECONNECT_INTERVAL_MS = 5000;
const MAX_ALERTS = 50;

interface UseAlertWebSocketOptions {
  url: string;
  enabled?: boolean;
}

interface UseAlertWebSocketResult {
  alerts: Alert[];
  connectionStatus: ConnectionStatus;
  unreadCount: number;
  markAllRead: () => void;
}

export function useAlertWebSocket({
  url,
  enabled = true,
}: UseAlertWebSocketOptions): UseAlertWebSocketResult {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('disconnected');
  const [unreadCount, setUnreadCount] = useState(0);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const enabledRef = useRef(enabled);

  enabledRef.current = enabled;

  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimerRef.current !== null) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  }, []);

  const connect = useCallback(() => {
    if (!enabledRef.current) return;

    clearReconnectTimer();

    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    setConnectionStatus('connecting');

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnectionStatus('connected');
    };

    ws.onmessage = (event: MessageEvent) => {
      try {
        const alert: Alert = JSON.parse(event.data as string);
        setAlerts((prev) => [alert, ...prev].slice(0, MAX_ALERTS));
        setUnreadCount((prev) => prev + 1);
      } catch {
        // Ignore malformed messages
      }
    };

    ws.onclose = () => {
      setConnectionStatus('disconnected');
      wsRef.current = null;

      if (enabledRef.current) {
        reconnectTimerRef.current = setTimeout(() => {
          connect();
        }, RECONNECT_INTERVAL_MS);
      }
    };

    ws.onerror = () => {
      // onclose will fire after onerror, triggering reconnect
    };
  }, [url, clearReconnectTimer]);

  useEffect(() => {
    if (enabled) {
      connect();
    }

    return () => {
      clearReconnectTimer();
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [enabled, connect, clearReconnectTimer]);

  const markAllRead = useCallback(() => {
    setUnreadCount(0);
  }, []);

  return {
    alerts,
    connectionStatus,
    unreadCount,
    markAllRead,
  };
}
