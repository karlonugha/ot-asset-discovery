import type { DeviceListResponse, DeviceFilters } from '../types/device';
import type { Alert } from '../types/alert';
import {
  mockDevices,
  mockAlerts,
  mockTopology,
  mockScanJobs,
  mockScanHistory,
  generateRandomAlert,
} from './mockData';
import type { TopologyResponse, ScanJob, ScanHistoryItem } from './mockData';

// --- Devices ---

interface FetchDevicesDemoParams {
  page: number;
  limit: number;
  filters: DeviceFilters;
}

export function fetchDevicesDemo({ page, limit, filters }: FetchDevicesDemoParams): DeviceListResponse {
  let filtered = [...mockDevices];

  if (filters.vendor) {
    const v = filters.vendor.toLowerCase();
    filtered = filtered.filter((d) => d.vendor?.toLowerCase().includes(v));
  }
  if (filters.model) {
    const m = filters.model.toLowerCase();
    filtered = filtered.filter((d) => d.model?.toLowerCase().includes(m));
  }
  if (filters.protocol) {
    const p = filters.protocol.toLowerCase();
    filtered = filtered.filter((d) => d.protocols.some((proto) => proto.toLowerCase().includes(p)));
  }
  if (filters.subnet) {
    // Simple prefix match for demo purposes
    const prefix = filters.subnet.split('/')[0].replace(/\.0$/, '');
    filtered = filtered.filter((d) => d.ip_address.startsWith(prefix));
  }
  if (filters.risk_score_min) {
    const min = Number(filters.risk_score_min);
    filtered = filtered.filter((d) => d.risk_score >= min);
  }
  if (filters.risk_score_max) {
    const max = Number(filters.risk_score_max);
    filtered = filtered.filter((d) => d.risk_score <= max);
  }

  const total = filtered.length;
  const offset = (page - 1) * limit;
  const devices = filtered.slice(offset, offset + limit);

  return { devices, total, limit, offset };
}

// --- Topology ---

export function fetchTopologyDemo(): TopologyResponse {
  return mockTopology;
}

// --- Alerts ---

export function fetchAlertsDemo(): Alert[] {
  return [...mockAlerts].sort(
    (a, b) => new Date(b.generated_at).getTime() - new Date(a.generated_at).getTime()
  );
}

// --- Scans ---

export function fetchScansDemo(): ScanJob[] {
  return [...mockScanJobs];
}

export function fetchScanHistoryDemo(scanId: string, page = 1, pageSize = 20): { items: ScanHistoryItem[]; total: number; page: number; page_size: number } {
  const history = mockScanHistory[scanId] ?? [];
  const total = history.length;
  const offset = (page - 1) * pageSize;
  const items = history.slice(offset, offset + pageSize);
  return { items, total, page, page_size: pageSize };
}

// --- Simulated Alert Stream ---

type AlertCallback = (alert: Alert) => void;

let intervalId: ReturnType<typeof setInterval> | null = null;
const subscribers: AlertCallback[] = [];

export function subscribeToDemoAlerts(callback: AlertCallback): () => void {
  subscribers.push(callback);

  // Start the interval if not already running
  if (intervalId === null) {
    intervalId = setInterval(() => {
      const alert = generateRandomAlert();
      subscribers.forEach((cb) => cb(alert));
    }, 8000 + Math.random() * 4000); // 8-12 seconds
  }

  // Return unsubscribe function
  return () => {
    const idx = subscribers.indexOf(callback);
    if (idx >= 0) subscribers.splice(idx, 1);
    if (subscribers.length === 0 && intervalId !== null) {
      clearInterval(intervalId);
      intervalId = null;
    }
  };
}
