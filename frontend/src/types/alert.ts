export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AlertType =
  | 'new_device'
  | 'device_disappeared'
  | 'firmware_change'
  | 'new_protocol'
  | 'risk_score_change'
  | 'scan_failed';

export interface Alert {
  id: string;
  alert_type: AlertType;
  severity: AlertSeverity;
  device_id: string | null;
  details: Record<string, unknown>;
  generated_at: string;
}
