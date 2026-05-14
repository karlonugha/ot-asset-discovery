import { useQuery, keepPreviousData } from '@tanstack/react-query';
import type { DeviceListResponse, DeviceFilters } from '../types/device';
import { fetchDevicesDemo } from '../data/demoApi';

const API_BASE = '/api/devices';

const isDemoMode = import.meta.env.VITE_DEMO_MODE === 'true';

interface UseDevicesParams {
  page: number;
  limit: number;
  filters: DeviceFilters;
}

async function fetchDevices({ page, limit, filters }: UseDevicesParams): Promise<DeviceListResponse> {
  // Demo mode: return mock data directly
  if (isDemoMode) {
    return fetchDevicesDemo({ page, limit, filters });
  }

  const offset = (page - 1) * limit;
  const params = new URLSearchParams();

  params.set('limit', String(limit));
  params.set('offset', String(offset));

  if (filters.vendor) params.set('vendor', filters.vendor);
  if (filters.model) params.set('model', filters.model);
  if (filters.protocol) params.set('protocol', filters.protocol);
  if (filters.subnet) params.set('subnet', filters.subnet);
  if (filters.risk_score_min) params.set('risk_score_min', filters.risk_score_min);
  if (filters.risk_score_max) params.set('risk_score_max', filters.risk_score_max);

  const response = await fetch(`${API_BASE}?${params.toString()}`);

  if (!response.ok) {
    throw new Error(`Failed to fetch devices: ${response.status}`);
  }

  return response.json();
}

export function useDevices(params: UseDevicesParams) {
  return useQuery({
    queryKey: ['devices', params.page, params.limit, params.filters],
    queryFn: () => fetchDevices(params),
    placeholderData: keepPreviousData,
  });
}
