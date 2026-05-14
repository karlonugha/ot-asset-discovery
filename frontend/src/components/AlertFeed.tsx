import { useState, useEffect, useRef, useCallback } from 'react';
import type { Alert, AlertSeverity } from '../types/alert';

const MAX_ALERTS = 50;
const RECONNECT_INTERVAL_MS = 5000;
const WS_BASE = 'ws://localhost:8000/ws/alerts';
const API_BASE = '/api/alerts';

type ConnectionStatus = 'connecting' | 'connected' | 'disconnected';

const SEVERITY_STYLES: Record<AlertSeverity, string> = {
  CRITICAL: 'border-l-red-700 bg-red-50',
  HIGH: 'border-l-orange-500 bg-orange-50',
  MEDIUM: 'border-l-yellow-500 bg-yellow-50',
  LOW: 'border-l-blue-400 bg-blue-50',
};

const SEVERITY_BADGE: Record<AlertSeverity, string> = {
  CRITICAL: 'bg-red-700 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-500 text-gray-900',
  LOW: 'bg-blue-400 text-white',
};

function formatAlertType(type: string): string {
  return type
    .split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

interface AlertFeedProps {
  token: string;
}

export function AlertFeed({ token }: AlertFeedProps) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('connecting');
  const [newAlertCount, setNewAlertCount] = useState(0);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Fetch initial alerts from REST API
  useEffect(() => {
    async function fetchAlerts() {
      try {
        const res = await fetch(`${API_BASE}?limit=${MAX_ALERTS}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) {
          setError(`Failed to fetch alerts: ${res.status}`);
          setLoading(false);
          return;
        }
        const data = await res.json();
        setAlerts(data.alerts ?? []);
        setLoading(false);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error');
        setLoading(false);
      }
    }
    fetchAlerts();
  }, [token]);

  // WebSocket connection
  const connectWebSocket = useCallback(() => {
    const ws = new WebSocket(`${WS_BASE}?token=${token}`);
    wsRef.current = ws;
    setConnectionStatus('connecting');

    ws.onopen = () => {
      setConnectionStatus('connected');
    };

    ws.onmessage = (event: MessageEvent) => {
      try {
        const alert: Alert = JSON.parse(event.data as string);
        setAlerts((prev) => [alert, ...prev].slice(0, MAX_ALERTS));
        setNewAlertCount((prev) => prev + 1);
      } catch {
        // Ignore malformed messages
      }
    };

    ws.onclose = () => {
      setConnectionStatus('disconnected');
      wsRef.current = null;
      // Attempt reconnect after interval
      reconnectTimerRef.current = setTimeout(() => {
        connectWebSocket();
      }, RECONNECT_INTERVAL_MS);
    };

    ws.onerror = () => {
      // onclose will fire after onerror
    };
  }, [token]);

  useEffect(() => {
    connectWebSocket();
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
    };
  }, [connectWebSocket]);

  const handleMarkAllRead = () => {
    setNewAlertCount(0);
  };

  const statusColor =
    connectionStatus === 'connected'
      ? 'bg-green-500'
      : connectionStatus === 'disconnected'
        ? 'bg-red-500'
        : 'bg-yellow-500';

  const statusLabel =
    connectionStatus === 'connected'
      ? 'Connected'
      : connectionStatus === 'disconnected'
        ? 'Disconnected'
        : 'Connecting';

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col tablet:flex-row tablet:items-center tablet:justify-between gap-3">
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-semibold text-gray-900">Alerts</h2>
          {newAlertCount > 0 && (
            <span
              aria-label={`${newAlertCount} new alerts`}
              className="inline-flex items-center justify-center px-2 py-0.5 text-xs font-bold text-white bg-red-600 rounded-full"
            >
              {newAlertCount}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {newAlertCount > 0 && (
            <button
              onClick={handleMarkAllRead}
              className="text-xs text-blue-600 hover:text-blue-800 font-medium"
            >
              Mark all read
            </button>
          )}
          <div className="flex items-center gap-1.5">
            <span
              className={`inline-block h-2.5 w-2.5 rounded-full ${statusColor}`}
              aria-label="WebSocket status"
            />
            <span className="text-xs text-gray-500">{statusLabel}</span>
          </div>
        </div>
      </div>

      {/* Content */}
      {loading && (
        <div className="p-8 text-center text-gray-500">Loading alerts...</div>
      )}

      {error && (
        <div className="p-8 text-center text-red-600">{error}</div>
      )}

      {!loading && !error && alerts.length === 0 && (
        <div className="p-8 text-center text-gray-500">No alerts yet</div>
      )}

      {!loading && !error && alerts.length > 0 && (
        <ul className="space-y-2 max-h-[500px] tablet:max-h-[600px] overflow-y-auto" role="list">
          {alerts.map((alert) => (
            <li
              key={alert.id}
              role="listitem"
              className={`border-l-4 rounded-r-md p-3 ${SEVERITY_STYLES[alert.severity]}`}
            >
              <div className="flex flex-col tablet:flex-row tablet:items-center tablet:justify-between gap-1">
                <div className="flex items-center gap-2">
                  <span
                    className={`inline-flex px-2 py-0.5 text-xs font-bold rounded ${SEVERITY_BADGE[alert.severity]}`}
                  >
                    {alert.severity}
                  </span>
                  <span className="text-sm font-medium text-gray-900">
                    {formatAlertType(alert.alert_type)}
                  </span>
                </div>
                <span className="text-xs text-gray-500">
                  {new Date(alert.generated_at).toLocaleString()}
                </span>
              </div>
              <p className="mt-1 text-xs text-gray-600 break-words">
                {JSON.stringify(alert.details)}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default AlertFeed;
