import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { DeviceInventoryTable } from './DeviceInventoryTable';
import type { DeviceListResponse } from '../types/device';

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
}

const mockDevices: DeviceListResponse = {
  devices: [
    {
      id: '1',
      ip_address: '192.168.1.10',
      mac_address: '00:1A:2B:3C:4D:5E',
      vendor: 'Siemens',
      model: 'S7-1200',
      firmware_version: '4.5.1',
      device_type: 'PLC',
      protocols: ['s7comm', 'modbus_tcp'],
      risk_score: 72,
      first_seen: '2024-01-01T00:00:00Z',
      last_seen: '2024-01-15T12:30:00Z',
    },
    {
      id: '2',
      ip_address: '192.168.1.20',
      mac_address: '00:1A:2B:3C:4D:6F',
      vendor: null,
      model: null,
      firmware_version: null,
      device_type: null,
      protocols: [],
      risk_score: 15,
      first_seen: '2024-01-02T00:00:00Z',
      last_seen: '2024-01-14T08:00:00Z',
    },
  ],
  total: 2,
  limit: 50,
  offset: 0,
};

const mockManyDevices: DeviceListResponse = {
  devices: Array.from({ length: 50 }, (_, i) => ({
    id: String(i + 1),
    ip_address: `192.168.1.${i + 1}`,
    mac_address: `00:1A:2B:3C:4D:${String(i).padStart(2, '0')}`,
    vendor: 'Vendor',
    model: 'Model',
    firmware_version: '1.0.0',
    device_type: 'PLC',
    protocols: ['modbus_tcp'],
    risk_score: i * 2,
    first_seen: '2024-01-01T00:00:00Z',
    last_seen: '2024-01-15T12:30:00Z',
  })),
  total: 120,
  limit: 50,
  offset: 0,
};

describe('DeviceInventoryTable', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders loading state initially', () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockImplementation(
      () => new Promise(() => {}) // never resolves
    );

    render(<DeviceInventoryTable />, { wrapper: createWrapper() });
    expect(screen.getByText('Loading devices...')).toBeInTheDocument();
  });

  it('renders device data after successful fetch', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => mockDevices,
    });

    render(<DeviceInventoryTable />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('192.168.1.10')).toBeInTheDocument();
    });

    expect(screen.getByText('00:1A:2B:3C:4D:5E')).toBeInTheDocument();
    expect(screen.getByText('Siemens')).toBeInTheDocument();
    expect(screen.getByText('S7-1200')).toBeInTheDocument();
    expect(screen.getByText('4.5.1')).toBeInTheDocument();
    expect(screen.getByText('s7comm')).toBeInTheDocument();
    expect(screen.getByText('modbus_tcp')).toBeInTheDocument();
    expect(screen.getByText('72')).toBeInTheDocument();
  });

  it('renders error state on fetch failure', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    render(<DeviceInventoryTable />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/Error loading devices/)).toBeInTheDocument();
    });
  });

  it('shows empty state when no devices match', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ devices: [], total: 0, limit: 50, offset: 0 }),
    });

    render(<DeviceInventoryTable />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(
        screen.getByText('No devices found matching the current filters.')
      ).toBeInTheDocument();
    });
  });

  it('displays pagination info and navigation controls', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => mockManyDevices,
    });

    render(<DeviceInventoryTable />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/Showing 1–50 of 120 devices/)).toBeInTheDocument();
    });

    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument();
    expect(screen.getByLabelText('Previous page')).toBeDisabled();
    expect(screen.getByLabelText('First page')).toBeDisabled();
    expect(screen.getByLabelText('Next page')).not.toBeDisabled();
    expect(screen.getByLabelText('Last page')).not.toBeDisabled();
  });

  it('navigates to next page when Next is clicked', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => mockManyDevices,
    });

    render(<DeviceInventoryTable />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('Page 1 of 3')).toBeInTheDocument();
    });

    const page2Response: DeviceListResponse = {
      ...mockManyDevices,
      offset: 50,
    };
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => page2Response,
    });

    fireEvent.click(screen.getByLabelText('Next page'));

    await waitFor(() => {
      expect(screen.getByText('Page 2 of 3')).toBeInTheDocument();
    });
  });

  it('sends filter parameters in API request', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => mockDevices,
    });

    render(<DeviceInventoryTable />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('192.168.1.10')).toBeInTheDocument();
    });

    // Fill in vendor filter
    fireEvent.change(screen.getByLabelText('Vendor'), {
      target: { value: 'Siemens' },
    });

    // Click Apply
    fireEvent.click(screen.getByText('Apply Filters'));

    await waitFor(() => {
      const lastCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.at(-1);
      expect(lastCall?.[0]).toContain('vendor=Siemens');
    });
  });

  it('clears filters when Clear button is clicked', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      json: async () => mockDevices,
    });

    render(<DeviceInventoryTable />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('192.168.1.10')).toBeInTheDocument();
    });

    // Set a filter
    fireEvent.change(screen.getByLabelText('Vendor'), {
      target: { value: 'Siemens' },
    });
    fireEvent.click(screen.getByText('Apply Filters'));

    await waitFor(() => {
      const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.at(-1);
      expect(call?.[0]).toContain('vendor=Siemens');
    });

    // Clear filters
    fireEvent.click(screen.getByText('Clear'));

    await waitFor(() => {
      const call = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.at(-1);
      expect(call?.[0]).not.toContain('vendor=');
    });
  });

  it('renders null fields with dash placeholder', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => mockDevices,
    });

    render(<DeviceInventoryTable />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('192.168.1.20')).toBeInTheDocument();
    });

    // The second device has null vendor/model/firmware — should show dashes
    const dashes = screen.getAllByText('—');
    expect(dashes.length).toBeGreaterThanOrEqual(3);
  });

  it('displays risk score with color coding', async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ok: true,
      json: async () => mockDevices,
    });

    render(<DeviceInventoryTable />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('72')).toBeInTheDocument();
    });

    // Risk score 72 should have orange styling
    const highRiskBadge = screen.getByText('72');
    expect(highRiskBadge.className).toContain('text-orange-700');

    // Risk score 15 should have green styling
    const lowRiskBadge = screen.getByText('15');
    expect(lowRiskBadge.className).toContain('text-green-700');
  });
});
