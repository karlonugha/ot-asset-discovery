export interface Device {
  id: string;
  ip_address: string;
  mac_address: string;
  vendor: string | null;
  model: string | null;
  firmware_version: string | null;
  device_type: string | null;
  protocols: string[];
  risk_score: number;
  first_seen: string;
  last_seen: string;
}

export interface DeviceListResponse {
  devices: Device[];
  total: number;
  limit: number;
  offset: number;
}

export interface DeviceFilters {
  vendor: string;
  model: string;
  protocol: string;
  subnet: string;
  risk_score_min: string;
  risk_score_max: string;
}
