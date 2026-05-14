import type { Device } from '../types/device';
import type { Alert, AlertType, AlertSeverity } from '../types/alert';

// --- Mock Devices ---

export const mockDevices: Device[] = [
  {
    id: 'dev-001',
    ip_address: '10.0.1.10',
    mac_address: '00:1A:2B:3C:4D:01',
    vendor: 'Siemens',
    model: 'S7-1200',
    firmware_version: 'V4.5.2',
    device_type: 'PLC',
    protocols: ['s7comm', 'modbus_tcp'],
    risk_score: 35,
    first_seen: '2024-11-15T08:30:00Z',
    last_seen: '2025-01-10T14:22:00Z',
  },
  {
    id: 'dev-002',
    ip_address: '10.0.1.11',
    mac_address: '00:1A:2B:3C:4D:02',
    vendor: 'Siemens',
    model: 'S7-300',
    firmware_version: 'V3.2.8',
    device_type: 'PLC',
    protocols: ['s7comm'],
    risk_score: 72,
    first_seen: '2024-09-01T10:00:00Z',
    last_seen: '2025-01-10T14:20:00Z',
  },
  {
    id: 'dev-003',
    ip_address: '10.0.1.12',
    mac_address: '00:1A:2B:3C:4D:03',
    vendor: 'Siemens',
    model: 'S7-1500',
    firmware_version: 'V2.9.4',
    device_type: 'PLC',
    protocols: ['s7comm', 'modbus_tcp'],
    risk_score: 18,
    first_seen: '2024-12-01T09:15:00Z',
    last_seen: '2025-01-10T14:25:00Z',
  },
  {
    id: 'dev-004',
    ip_address: '10.0.1.20',
    mac_address: '00:1A:2B:3C:4D:04',
    vendor: 'Allen-Bradley',
    model: 'CompactLogix 5380',
    firmware_version: 'V33.011',
    device_type: 'PLC',
    protocols: ['ethernetip'],
    risk_score: 42,
    first_seen: '2024-10-20T11:00:00Z',
    last_seen: '2025-01-10T14:18:00Z',
  },
  {
    id: 'dev-005',
    ip_address: '10.0.1.21',
    mac_address: '00:1A:2B:3C:4D:05',
    vendor: 'Allen-Bradley',
    model: 'ControlLogix 5580',
    firmware_version: 'V34.014',
    device_type: 'PLC',
    protocols: ['ethernetip', 'modbus_tcp'],
    risk_score: 28,
    first_seen: '2024-08-15T07:45:00Z',
    last_seen: '2025-01-10T14:21:00Z',
  },
  {
    id: 'dev-006',
    ip_address: '10.0.1.30',
    mac_address: '00:1A:2B:3C:4D:06',
    vendor: 'Schneider Electric',
    model: 'Modicon M221',
    firmware_version: 'V1.10.2.0',
    device_type: 'PLC',
    protocols: ['modbus_tcp'],
    risk_score: 88,
    first_seen: '2024-07-10T06:30:00Z',
    last_seen: '2025-01-10T14:19:00Z',
  },
  {
    id: 'dev-007',
    ip_address: '10.0.1.31',
    mac_address: '00:1A:2B:3C:4D:07',
    vendor: 'Schneider Electric',
    model: 'Modicon M340',
    firmware_version: 'V3.40',
    device_type: 'PLC',
    protocols: ['modbus_tcp', 'ethernetip'],
    risk_score: 55,
    first_seen: '2024-06-22T12:00:00Z',
    last_seen: '2025-01-10T14:23:00Z',
  },
  {
    id: 'dev-008',
    ip_address: '192.168.100.10',
    mac_address: '00:1A:2B:3C:4D:08',
    vendor: 'ABB',
    model: 'AC500 PM5675',
    firmware_version: 'V3.1.0',
    device_type: 'PLC',
    protocols: ['modbus_tcp', 'ethernetip'],
    risk_score: 31,
    first_seen: '2024-11-01T09:00:00Z',
    last_seen: '2025-01-10T14:24:00Z',
  },
  {
    id: 'dev-009',
    ip_address: '192.168.100.11',
    mac_address: '00:1A:2B:3C:4D:09',
    vendor: 'Honeywell',
    model: 'C300 Controller',
    firmware_version: 'R520.1',
    device_type: 'PLC',
    protocols: ['modbus_tcp'],
    risk_score: 67,
    first_seen: '2024-05-18T14:30:00Z',
    last_seen: '2025-01-10T14:17:00Z',
  },
  {
    id: 'dev-010',
    ip_address: '192.168.100.20',
    mac_address: '00:1A:2B:3C:4D:10',
    vendor: 'GE',
    model: 'D60 Line Distance Relay',
    firmware_version: 'V8.30',
    device_type: 'IED',
    protocols: ['dnp3', 'modbus_tcp'],
    risk_score: 45,
    first_seen: '2024-04-10T08:00:00Z',
    last_seen: '2025-01-10T14:16:00Z',
  },
  {
    id: 'dev-011',
    ip_address: '192.168.100.21',
    mac_address: '00:1A:2B:3C:4D:11',
    vendor: 'SEL',
    model: 'SEL-751',
    firmware_version: 'R302-V0',
    device_type: 'IED',
    protocols: ['dnp3'],
    risk_score: 52,
    first_seen: '2024-03-25T10:15:00Z',
    last_seen: '2025-01-10T14:15:00Z',
  },
  {
    id: 'dev-012',
    ip_address: '192.168.100.22',
    mac_address: '00:1A:2B:3C:4D:12',
    vendor: 'SEL',
    model: 'SEL-751',
    firmware_version: 'R301-V2',
    device_type: 'IED',
    protocols: ['dnp3', 'modbus_tcp'],
    risk_score: 92,
    first_seen: '2024-02-14T11:45:00Z',
    last_seen: '2025-01-09T22:30:00Z',
  },
  {
    id: 'dev-013',
    ip_address: '10.0.1.50',
    mac_address: '00:1A:2B:3C:4D:13',
    vendor: 'Yokogawa',
    model: 'CENTUM VP',
    firmware_version: 'R6.09',
    device_type: 'PLC',
    protocols: ['modbus_tcp'],
    risk_score: 38,
    first_seen: '2024-10-05T13:00:00Z',
    last_seen: '2025-01-10T14:26:00Z',
  },
  {
    id: 'dev-014',
    ip_address: '10.0.1.100',
    mac_address: '00:1A:2B:3C:4D:14',
    vendor: 'Siemens',
    model: 'SIMATIC HMI TP1500',
    firmware_version: 'V17.0.5',
    device_type: 'HMI',
    protocols: ['s7comm'],
    risk_score: 25,
    first_seen: '2024-11-20T08:00:00Z',
    last_seen: '2025-01-10T14:27:00Z',
  },
  {
    id: 'dev-015',
    ip_address: '10.0.1.101',
    mac_address: '00:1A:2B:3C:4D:15',
    vendor: 'Allen-Bradley',
    model: 'PanelView Plus 7',
    firmware_version: 'V12.011',
    device_type: 'HMI',
    protocols: ['ethernetip'],
    risk_score: 15,
    first_seen: '2024-12-10T09:30:00Z',
    last_seen: '2025-01-10T14:28:00Z',
  },
  {
    id: 'dev-016',
    ip_address: '192.168.100.50',
    mac_address: '00:1A:2B:3C:4D:16',
    vendor: 'Schneider Electric',
    model: 'Magelis HMIGTO',
    firmware_version: 'V3.2',
    device_type: 'HMI',
    protocols: ['modbus_tcp'],
    risk_score: 60,
    first_seen: '2024-09-15T07:00:00Z',
    last_seen: '2025-01-10T14:12:00Z',
  },
  {
    id: 'dev-017',
    ip_address: '192.168.100.60',
    mac_address: '00:1A:2B:3C:4D:17',
    vendor: 'ABB',
    model: 'RTU560',
    firmware_version: 'V12.4.1',
    device_type: 'RTU',
    protocols: ['dnp3', 'modbus_tcp'],
    risk_score: 78,
    first_seen: '2024-08-01T06:00:00Z',
    last_seen: '2025-01-10T14:10:00Z',
  },
  {
    id: 'dev-018',
    ip_address: '192.168.100.61',
    mac_address: '00:1A:2B:3C:4D:18',
    vendor: 'GE',
    model: 'D400 RTU',
    firmware_version: 'V5.21',
    device_type: 'RTU',
    protocols: ['dnp3'],
    risk_score: 5,
    first_seen: '2025-01-05T15:00:00Z',
    last_seen: '2025-01-10T14:30:00Z',
  },
  {
    id: 'dev-019',
    ip_address: '10.0.1.55',
    mac_address: '00:1A:2B:3C:4D:19',
    vendor: 'Siemens',
    model: 'S7-1200',
    firmware_version: 'V4.4.0',
    device_type: 'PLC',
    protocols: ['s7comm', 'modbus_tcp'],
    risk_score: 48,
    first_seen: '2024-10-12T10:30:00Z',
    last_seen: '2025-01-10T14:05:00Z',
  },
];

// --- Mock Alerts ---


export const mockAlerts: Alert[] = [
  {
    id: 'alert-001',
    alert_type: 'new_device',
    severity: 'HIGH',
    device_id: 'dev-018',
    details: { ip_address: '192.168.100.61', vendor: 'GE', model: 'D400 RTU' },
    generated_at: '2025-01-10T14:30:00Z',
  },
  {
    id: 'alert-002',
    alert_type: 'firmware_change',
    severity: 'CRITICAL',
    device_id: 'dev-006',
    details: { old_version: 'V1.9.1.0', new_version: 'V1.10.2.0', ip_address: '10.0.1.30' },
    generated_at: '2025-01-10T13:45:00Z',
  },
  {
    id: 'alert-003',
    alert_type: 'risk_score_change',
    severity: 'HIGH',
    device_id: 'dev-012',
    details: { old_score: 65, new_score: 92, ip_address: '192.168.100.22' },
    generated_at: '2025-01-10T13:30:00Z',
  },
  {
    id: 'alert-004',
    alert_type: 'device_disappeared',
    severity: 'MEDIUM',
    device_id: 'dev-012',
    details: { ip_address: '192.168.100.22', last_seen: '2025-01-09T22:30:00Z' },
    generated_at: '2025-01-10T12:00:00Z',
  },
  {
    id: 'alert-005',
    alert_type: 'new_protocol',
    severity: 'MEDIUM',
    device_id: 'dev-005',
    details: { protocol: 'modbus_tcp', ip_address: '10.0.1.21' },
    generated_at: '2025-01-10T11:15:00Z',
  },
  {
    id: 'alert-006',
    alert_type: 'risk_score_change',
    severity: 'HIGH',
    device_id: 'dev-017',
    details: { old_score: 55, new_score: 78, ip_address: '192.168.100.60' },
    generated_at: '2025-01-10T10:30:00Z',
  },
  {
    id: 'alert-007',
    alert_type: 'new_device',
    severity: 'MEDIUM',
    device_id: 'dev-019',
    details: { ip_address: '10.0.1.55', vendor: 'Siemens', model: 'S7-1200' },
    generated_at: '2025-01-10T10:00:00Z',
  },
  {
    id: 'alert-008',
    alert_type: 'firmware_change',
    severity: 'HIGH',
    device_id: 'dev-002',
    details: { old_version: 'V3.2.6', new_version: 'V3.2.8', ip_address: '10.0.1.11' },
    generated_at: '2025-01-10T09:45:00Z',
  },
  {
    id: 'alert-009',
    alert_type: 'new_protocol',
    severity: 'LOW',
    device_id: 'dev-007',
    details: { protocol: 'ethernetip', ip_address: '10.0.1.31' },
    generated_at: '2025-01-10T09:00:00Z',
  },
  {
    id: 'alert-010',
    alert_type: 'risk_score_change',
    severity: 'MEDIUM',
    device_id: 'dev-016',
    details: { old_score: 40, new_score: 60, ip_address: '192.168.100.50' },
    generated_at: '2025-01-10T08:30:00Z',
  },
  {
    id: 'alert-011',
    alert_type: 'device_disappeared',
    severity: 'HIGH',
    device_id: null,
    details: { ip_address: '10.0.1.99', last_seen: '2025-01-08T18:00:00Z' },
    generated_at: '2025-01-09T22:00:00Z',
  },
  {
    id: 'alert-012',
    alert_type: 'new_device',
    severity: 'MEDIUM',
    device_id: 'dev-013',
    details: { ip_address: '10.0.1.50', vendor: 'Yokogawa', model: 'CENTUM VP' },
    generated_at: '2025-01-09T20:00:00Z',
  },
  {
    id: 'alert-013',
    alert_type: 'firmware_change',
    severity: 'CRITICAL',
    device_id: 'dev-012',
    details: { old_version: 'R300-V1', new_version: 'R301-V2', ip_address: '192.168.100.22' },
    generated_at: '2025-01-09T18:30:00Z',
  },
  {
    id: 'alert-014',
    alert_type: 'risk_score_change',
    severity: 'LOW',
    device_id: 'dev-004',
    details: { old_score: 38, new_score: 42, ip_address: '10.0.1.20' },
    generated_at: '2025-01-09T16:00:00Z',
  },
  {
    id: 'alert-015',
    alert_type: 'new_protocol',
    severity: 'MEDIUM',
    device_id: 'dev-012',
    details: { protocol: 'modbus_tcp', ip_address: '192.168.100.22' },
    generated_at: '2025-01-09T14:45:00Z',
  },
  {
    id: 'alert-016',
    alert_type: 'new_device',
    severity: 'HIGH',
    device_id: 'dev-017',
    details: { ip_address: '192.168.100.60', vendor: 'ABB', model: 'RTU560' },
    generated_at: '2025-01-09T12:00:00Z',
  },
  {
    id: 'alert-017',
    alert_type: 'device_disappeared',
    severity: 'LOW',
    device_id: null,
    details: { ip_address: '10.0.1.88', last_seen: '2025-01-07T10:00:00Z' },
    generated_at: '2025-01-09T10:00:00Z',
  },
  {
    id: 'alert-018',
    alert_type: 'risk_score_change',
    severity: 'CRITICAL',
    device_id: 'dev-006',
    details: { old_score: 62, new_score: 88, ip_address: '10.0.1.30' },
    generated_at: '2025-01-09T08:15:00Z',
  },
  {
    id: 'alert-019',
    alert_type: 'firmware_change',
    severity: 'MEDIUM',
    device_id: 'dev-009',
    details: { old_version: 'R510.2', new_version: 'R520.1', ip_address: '192.168.100.11' },
    generated_at: '2025-01-08T22:00:00Z',
  },
  {
    id: 'alert-020',
    alert_type: 'new_protocol',
    severity: 'HIGH',
    device_id: 'dev-017',
    details: { protocol: 'dnp3', ip_address: '192.168.100.60' },
    generated_at: '2025-01-08T20:30:00Z',
  },
  {
    id: 'alert-021',
    alert_type: 'new_device',
    severity: 'LOW',
    device_id: 'dev-015',
    details: { ip_address: '10.0.1.101', vendor: 'Allen-Bradley', model: 'PanelView Plus 7' },
    generated_at: '2025-01-08T18:00:00Z',
  },
  {
    id: 'alert-022',
    alert_type: 'risk_score_change',
    severity: 'MEDIUM',
    device_id: 'dev-002',
    details: { old_score: 58, new_score: 72, ip_address: '10.0.1.11' },
    generated_at: '2025-01-08T15:30:00Z',
  },
  {
    id: 'alert-023',
    alert_type: 'device_disappeared',
    severity: 'HIGH',
    device_id: null,
    details: { ip_address: '192.168.100.99', last_seen: '2025-01-06T12:00:00Z' },
    generated_at: '2025-01-08T12:00:00Z',
  },
  {
    id: 'alert-024',
    alert_type: 'firmware_change',
    severity: 'LOW',
    device_id: 'dev-003',
    details: { old_version: 'V2.9.2', new_version: 'V2.9.4', ip_address: '10.0.1.12' },
    generated_at: '2025-01-08T09:00:00Z',
  },
  {
    id: 'alert-025',
    alert_type: 'new_protocol',
    severity: 'MEDIUM',
    device_id: 'dev-008',
    details: { protocol: 'ethernetip', ip_address: '192.168.100.10' },
    generated_at: '2025-01-07T22:00:00Z',
  },
  {
    id: 'alert-026',
    alert_type: 'risk_score_change',
    severity: 'LOW',
    device_id: 'dev-011',
    details: { old_score: 48, new_score: 52, ip_address: '192.168.100.21' },
    generated_at: '2025-01-07T18:00:00Z',
  },
  {
    id: 'alert-027',
    alert_type: 'new_device',
    severity: 'MEDIUM',
    device_id: 'dev-014',
    details: { ip_address: '10.0.1.100', vendor: 'Siemens', model: 'SIMATIC HMI TP1500' },
    generated_at: '2025-01-07T14:00:00Z',
  },
  {
    id: 'alert-028',
    alert_type: 'device_disappeared',
    severity: 'MEDIUM',
    device_id: null,
    details: { ip_address: '10.0.1.77', last_seen: '2025-01-05T08:00:00Z' },
    generated_at: '2025-01-07T10:00:00Z',
  },
  {
    id: 'alert-029',
    alert_type: 'firmware_change',
    severity: 'HIGH',
    device_id: 'dev-011',
    details: { old_version: 'R301-V0', new_version: 'R302-V0', ip_address: '192.168.100.21' },
    generated_at: '2025-01-07T08:00:00Z',
  },
  {
    id: 'alert-030',
    alert_type: 'risk_score_change',
    severity: 'MEDIUM',
    device_id: 'dev-009',
    details: { old_score: 50, new_score: 67, ip_address: '192.168.100.11' },
    generated_at: '2025-01-06T22:00:00Z',
  },
  {
    id: 'alert-031',
    alert_type: 'new_protocol',
    severity: 'LOW',
    device_id: 'dev-001',
    details: { protocol: 'modbus_tcp', ip_address: '10.0.1.10' },
    generated_at: '2025-01-06T18:00:00Z',
  },
  {
    id: 'alert-032',
    alert_type: 'new_device',
    severity: 'HIGH',
    device_id: 'dev-016',
    details: { ip_address: '192.168.100.50', vendor: 'Schneider Electric', model: 'Magelis HMIGTO' },
    generated_at: '2025-01-06T14:00:00Z',
  },
];

// --- Mock Topology ---

export interface TopologyNode {
  device_id: string;
  name: string | null;
  ip_address: string;
  device_type: string | null;
}

export interface TopologyEdge {
  source_device_id: string;
  dest_device_id: string;
  protocol: string;
  packet_count: number;
  last_seen: string;
}

export interface TopologyResponse {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  stale: boolean;
  last_updated: string | null;
}

export const mockTopology: TopologyResponse = {
  nodes: mockDevices.map((d) => ({
    device_id: d.id,
    name: d.model,
    ip_address: d.ip_address,
    device_type: d.device_type,
  })),
  edges: [
    // HMI -> PLC communications
    { source_device_id: 'dev-014', dest_device_id: 'dev-001', protocol: 's7comm', packet_count: 14520, last_seen: '2025-01-10T14:22:00Z' },
    { source_device_id: 'dev-014', dest_device_id: 'dev-002', protocol: 's7comm', packet_count: 9830, last_seen: '2025-01-10T14:20:00Z' },
    { source_device_id: 'dev-014', dest_device_id: 'dev-003', protocol: 's7comm', packet_count: 11200, last_seen: '2025-01-10T14:25:00Z' },
    { source_device_id: 'dev-015', dest_device_id: 'dev-004', protocol: 'ethernetip', packet_count: 8900, last_seen: '2025-01-10T14:18:00Z' },
    { source_device_id: 'dev-015', dest_device_id: 'dev-005', protocol: 'ethernetip', packet_count: 7650, last_seen: '2025-01-10T14:21:00Z' },
    { source_device_id: 'dev-016', dest_device_id: 'dev-006', protocol: 'modbus_tcp', packet_count: 5400, last_seen: '2025-01-10T14:19:00Z' },
    { source_device_id: 'dev-016', dest_device_id: 'dev-007', protocol: 'modbus_tcp', packet_count: 6100, last_seen: '2025-01-10T14:23:00Z' },
    // PLC-to-PLC communications
    { source_device_id: 'dev-001', dest_device_id: 'dev-019', protocol: 's7comm', packet_count: 3200, last_seen: '2025-01-10T14:05:00Z' },
    { source_device_id: 'dev-004', dest_device_id: 'dev-005', protocol: 'ethernetip', packet_count: 4500, last_seen: '2025-01-10T14:21:00Z' },
    { source_device_id: 'dev-006', dest_device_id: 'dev-007', protocol: 'modbus_tcp', packet_count: 2800, last_seen: '2025-01-10T14:23:00Z' },
    // RTU -> IED communications
    { source_device_id: 'dev-017', dest_device_id: 'dev-010', protocol: 'dnp3', packet_count: 6700, last_seen: '2025-01-10T14:16:00Z' },
    { source_device_id: 'dev-017', dest_device_id: 'dev-011', protocol: 'dnp3', packet_count: 5900, last_seen: '2025-01-10T14:15:00Z' },
    { source_device_id: 'dev-017', dest_device_id: 'dev-012', protocol: 'dnp3', packet_count: 4100, last_seen: '2025-01-09T22:30:00Z' },
    { source_device_id: 'dev-018', dest_device_id: 'dev-010', protocol: 'dnp3', packet_count: 3300, last_seen: '2025-01-10T14:30:00Z' },
    { source_device_id: 'dev-018', dest_device_id: 'dev-011', protocol: 'dnp3', packet_count: 2900, last_seen: '2025-01-10T14:15:00Z' },
    // PLC -> RTU
    { source_device_id: 'dev-008', dest_device_id: 'dev-017', protocol: 'modbus_tcp', packet_count: 1800, last_seen: '2025-01-10T14:10:00Z' },
    { source_device_id: 'dev-009', dest_device_id: 'dev-013', protocol: 'modbus_tcp', packet_count: 2200, last_seen: '2025-01-10T14:26:00Z' },
    // Cross-subnet
    { source_device_id: 'dev-003', dest_device_id: 'dev-008', protocol: 'modbus_tcp', packet_count: 1500, last_seen: '2025-01-10T14:24:00Z' },
    { source_device_id: 'dev-005', dest_device_id: 'dev-009', protocol: 'modbus_tcp', packet_count: 1100, last_seen: '2025-01-10T14:17:00Z' },
  ],
  stale: false,
  last_updated: '2025-01-10T14:30:00Z',
};

// --- Mock Scan Jobs ---

export interface ScanJob {
  id: string;
  name: string;
  schedule: string | null;
  target_subnet: string | null;
  active_probing_enabled: boolean;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  devices_discovered: number;
  new_devices: number;
  alerts_generated: number;
  failure_reason: string | null;
  created_at: string;
  updated_at: string;
}

export interface ScanHistoryItem {
  id: string;
  scan_job_id: string;
  status: string;
  started_at: string;
  completed_at: string | null;
  devices_discovered: number;
  new_devices: number;
  alerts_generated: number;
  failure_reason: string | null;
}

export const mockScanJobs: ScanJob[] = [
  {
    id: 'scan-001',
    name: 'Full Network Discovery',
    schedule: '0 */6 * * *',
    target_subnet: null,
    active_probing_enabled: true,
    status: 'completed',
    started_at: '2025-01-10T12:00:00Z',
    completed_at: '2025-01-10T12:08:32Z',
    devices_discovered: 19,
    new_devices: 1,
    alerts_generated: 3,
    failure_reason: null,
    created_at: '2024-11-01T08:00:00Z',
    updated_at: '2025-01-10T12:08:32Z',
  },
  {
    id: 'scan-002',
    name: 'Control Network Scan',
    schedule: '*/30 * * * *',
    target_subnet: '10.0.1.0/24',
    active_probing_enabled: false,
    status: 'completed',
    started_at: '2025-01-10T14:00:00Z',
    completed_at: '2025-01-10T14:03:15Z',
    devices_discovered: 11,
    new_devices: 0,
    alerts_generated: 1,
    failure_reason: null,
    created_at: '2024-11-15T10:00:00Z',
    updated_at: '2025-01-10T14:03:15Z',
  },
  {
    id: 'scan-003',
    name: 'Substation Network',
    schedule: '0 */2 * * *',
    target_subnet: '192.168.100.0/24',
    active_probing_enabled: true,
    status: 'completed',
    started_at: '2025-01-10T14:00:00Z',
    completed_at: '2025-01-10T14:05:44Z',
    devices_discovered: 8,
    new_devices: 0,
    alerts_generated: 2,
    failure_reason: null,
    created_at: '2024-12-01T09:00:00Z',
    updated_at: '2025-01-10T14:05:44Z',
  },
  {
    id: 'scan-004',
    name: 'Deep Protocol Analysis',
    schedule: null,
    target_subnet: null,
    active_probing_enabled: true,
    status: 'scheduled',
    started_at: null,
    completed_at: null,
    devices_discovered: 0,
    new_devices: 0,
    alerts_generated: 0,
    failure_reason: null,
    created_at: '2025-01-09T16:00:00Z',
    updated_at: '2025-01-09T16:00:00Z',
  },
];

export const mockScanHistory: Record<string, ScanHistoryItem[]> = {
  'scan-001': [
    { id: 'hist-001', scan_job_id: 'scan-001', status: 'completed', started_at: '2025-01-10T12:00:00Z', completed_at: '2025-01-10T12:08:32Z', devices_discovered: 19, new_devices: 1, alerts_generated: 3, failure_reason: null },
    { id: 'hist-002', scan_job_id: 'scan-001', status: 'completed', started_at: '2025-01-10T06:00:00Z', completed_at: '2025-01-10T06:07:55Z', devices_discovered: 18, new_devices: 0, alerts_generated: 1, failure_reason: null },
    { id: 'hist-003', scan_job_id: 'scan-001', status: 'completed', started_at: '2025-01-10T00:00:00Z', completed_at: '2025-01-10T00:09:10Z', devices_discovered: 18, new_devices: 0, alerts_generated: 0, failure_reason: null },
    { id: 'hist-004', scan_job_id: 'scan-001', status: 'failed', started_at: '2025-01-09T18:00:00Z', completed_at: '2025-01-09T18:01:02Z', devices_discovered: 0, new_devices: 0, alerts_generated: 0, failure_reason: 'Network timeout on 10.0.1.0/24' },
    { id: 'hist-005', scan_job_id: 'scan-001', status: 'completed', started_at: '2025-01-09T12:00:00Z', completed_at: '2025-01-09T12:08:20Z', devices_discovered: 18, new_devices: 2, alerts_generated: 4, failure_reason: null },
  ],
  'scan-002': [
    { id: 'hist-006', scan_job_id: 'scan-002', status: 'completed', started_at: '2025-01-10T14:00:00Z', completed_at: '2025-01-10T14:03:15Z', devices_discovered: 11, new_devices: 0, alerts_generated: 1, failure_reason: null },
    { id: 'hist-007', scan_job_id: 'scan-002', status: 'completed', started_at: '2025-01-10T13:30:00Z', completed_at: '2025-01-10T13:33:05Z', devices_discovered: 11, new_devices: 0, alerts_generated: 0, failure_reason: null },
    { id: 'hist-008', scan_job_id: 'scan-002', status: 'completed', started_at: '2025-01-10T13:00:00Z', completed_at: '2025-01-10T13:02:58Z', devices_discovered: 11, new_devices: 0, alerts_generated: 2, failure_reason: null },
  ],
  'scan-003': [
    { id: 'hist-009', scan_job_id: 'scan-003', status: 'completed', started_at: '2025-01-10T14:00:00Z', completed_at: '2025-01-10T14:05:44Z', devices_discovered: 8, new_devices: 0, alerts_generated: 2, failure_reason: null },
    { id: 'hist-010', scan_job_id: 'scan-003', status: 'completed', started_at: '2025-01-10T12:00:00Z', completed_at: '2025-01-10T12:04:30Z', devices_discovered: 8, new_devices: 1, alerts_generated: 3, failure_reason: null },
  ],
  'scan-004': [],
};

// --- Random Alert Generator ---

const alertTypes: AlertType[] = ['new_device', 'device_disappeared', 'firmware_change', 'new_protocol', 'risk_score_change'];
const severities: AlertSeverity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

let alertCounter = 100;

export function generateRandomAlert(): Alert {
  alertCounter++;
  const device = mockDevices[Math.floor(Math.random() * mockDevices.length)];
  const alertType = alertTypes[Math.floor(Math.random() * alertTypes.length)];
  const severity = severities[Math.floor(Math.random() * severities.length)];

  let details: Record<string, unknown> = {};

  switch (alertType) {
    case 'new_device':
      details = { ip_address: device.ip_address, vendor: device.vendor, model: device.model };
      break;
    case 'device_disappeared':
      details = { ip_address: device.ip_address, last_seen: device.last_seen };
      break;
    case 'firmware_change':
      details = { old_version: 'V' + Math.floor(Math.random() * 5) + '.0', new_version: device.firmware_version, ip_address: device.ip_address };
      break;
    case 'new_protocol':
      details = { protocol: device.protocols[Math.floor(Math.random() * device.protocols.length)], ip_address: device.ip_address };
      break;
    case 'risk_score_change':
      details = { old_score: Math.max(0, device.risk_score - Math.floor(Math.random() * 20)), new_score: device.risk_score, ip_address: device.ip_address };
      break;
  }

  return {
    id: `alert-gen-${alertCounter}`,
    alert_type: alertType,
    severity,
    device_id: device.id,
    details,
    generated_at: new Date().toISOString(),
  };
}
