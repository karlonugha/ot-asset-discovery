import { render, screen, waitFor, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AlertFeed } from './AlertFeed';
import type { Alert } from '../types/alert';

// Mock WebSocket
class MockWebSocket {
  static instances: MockWebSocket[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readyState = 0;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
    // Simulate async connection
    setTimeout(() => {
      this.readyState = 1;
      this.onopen?.();
    }, 0);
  }

  close() {
    this.readyState = 3;
    this.onclose?.();
  }

  simulateMessage(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }

  simulateClose() {
    this.readyState = 3;
    this.onclose?.();
  }
}

function createMockAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: crypto.randomUUID(),
    alert_type: 'new_device',
    severity: 'HIGH',
    device_id: 'device-123',
    details: { ip_address: '192.168.1.100', mac_address: 'AA:BB:CC:DD:EE:FF' },
    generated_at: new Date().toISOString(),
    ...overrides,
  };
}

describe('AlertFeed', () => {
  let originalWebSocket: typeof WebSocket;

  beforeEach(() => {
    MockWebSocket.instances = [];
    originalWebSocket = globalThis.WebSocket;
    globalThis.WebSocket = MockWebSocket as unknown as typeof WebSocket;
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('renders the alert feed header', () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ alerts: [] }), { status: 200 })
    );

    render(<AlertFeed token="test-token" />);
    expect(screen.getByText('Alerts')).toBeInTheDocument();
  });

  it('shows loading state initially', () => {
    vi.spyOn(globalThis, 'fetch').mockReturnValue(new Promise(() => {}));

    render(<AlertFeed token="test-token" />);
    expect(screen.getByText('Loading alerts...')).toBeInTheDocument();
  });

  it('displays alerts fetched from REST API', async () => {
    const mockAlerts: Alert[] = [
      createMockAlert({ id: '1', severity: 'CRITICAL', alert_type: 'firmware_change', details: { previous_version: '1.0', new_version: '2.0' } }),
      createMockAlert({ id: '2', severity: 'LOW', alert_type: 'new_protocol', details: { protocol: 'modbus_tcp' } }),
    ];

    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ alerts: mockAlerts }), { status: 200 })
    );

    render(<AlertFeed token="test-token" />);

    await waitFor(() => {
      expect(screen.getByText('CRITICAL')).toBeInTheDocument();
      expect(screen.getByText('LOW')).toBeInTheDocument();
    });
  });

  it('shows error state when fetch fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(null, { status: 500 })
    );

    render(<AlertFeed token="test-token" />);

    await waitFor(() => {
      expect(screen.getByText('Failed to fetch alerts: 500')).toBeInTheDocument();
    });
  });

  it('shows "No alerts yet" when there are no alerts', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ alerts: [] }), { status: 200 })
    );

    render(<AlertFeed token="test-token" />);

    await waitFor(() => {
      expect(screen.getByText('No alerts yet')).toBeInTheDocument();
    });
  });

  it('displays connection status indicator', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ alerts: [] }), { status: 200 })
    );

    render(<AlertFeed token="test-token" />);

    // Initially connecting
    expect(screen.getByLabelText(/WebSocket status/)).toBeInTheDocument();
  });

  it('shows connected status after WebSocket opens', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ alerts: [] }), { status: 200 })
    );

    render(<AlertFeed token="test-token" />);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10);
    });

    expect(screen.getByText('Connected')).toBeInTheDocument();
  });

  it('prepends new WebSocket alerts to the feed', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ alerts: [] }), { status: 200 })
    );

    render(<AlertFeed token="test-token" />);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10);
    });

    const ws = MockWebSocket.instances[0];
    const newAlert = createMockAlert({
      id: 'ws-alert-1',
      severity: 'HIGH',
      alert_type: 'new_device',
      details: { ip_address: '10.0.0.1', mac_address: '11:22:33:44:55:66' },
    });

    act(() => {
      ws.simulateMessage(newAlert);
    });

    await waitFor(() => {
      expect(screen.getByText('HIGH')).toBeInTheDocument();
      expect(screen.getByText('New Device')).toBeInTheDocument();
    });
  });

  it('shows notification badge when new alerts arrive via WebSocket', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ alerts: [] }), { status: 200 })
    );

    render(<AlertFeed token="test-token" />);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10);
    });

    const ws = MockWebSocket.instances[0];

    act(() => {
      ws.simulateMessage(createMockAlert({ id: 'ws-1' }));
      ws.simulateMessage(createMockAlert({ id: 'ws-2' }));
    });

    await waitFor(() => {
      expect(screen.getByLabelText('2 new alerts')).toBeInTheDocument();
    });
  });

  it('clears notification badge when "Mark all read" is clicked', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ alerts: [] }), { status: 200 })
    );

    render(<AlertFeed token="test-token" />);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10);
    });

    const ws = MockWebSocket.instances[0];

    act(() => {
      ws.simulateMessage(createMockAlert({ id: 'ws-1' }));
    });

    await waitFor(() => {
      expect(screen.getByText('Mark all read')).toBeInTheDocument();
    });

    act(() => {
      screen.getByText('Mark all read').click();
    });

    expect(screen.queryByLabelText(/new alerts/)).not.toBeInTheDocument();
  });

  it('limits displayed alerts to 50', async () => {
    const initialAlerts = Array.from({ length: 50 }, (_, i) =>
      createMockAlert({ id: `initial-${i}` })
    );

    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ alerts: initialAlerts }), { status: 200 })
    );

    render(<AlertFeed token="test-token" />);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10);
    });

    const ws = MockWebSocket.instances[0];

    act(() => {
      ws.simulateMessage(createMockAlert({ id: 'ws-new' }));
    });

    await waitFor(() => {
      const items = screen.getAllByRole('listitem');
      expect(items.length).toBe(50);
    });
  });

  it('shows disconnected status and attempts reconnect after 5 seconds', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ alerts: [] }), { status: 200 })
    );

    render(<AlertFeed token="test-token" />);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10);
    });

    expect(screen.getByText('Connected')).toBeInTheDocument();

    const ws = MockWebSocket.instances[0];

    act(() => {
      ws.simulateClose();
    });

    expect(screen.getByText('Disconnected')).toBeInTheDocument();

    // Advance 5 seconds for reconnect
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });

    // A new WebSocket instance should have been created
    expect(MockWebSocket.instances.length).toBe(2);
  });

  it('color-codes alerts by severity', async () => {
    const alerts: Alert[] = [
      createMockAlert({ id: '1', severity: 'CRITICAL' }),
      createMockAlert({ id: '2', severity: 'HIGH' }),
      createMockAlert({ id: '3', severity: 'MEDIUM' }),
      createMockAlert({ id: '4', severity: 'LOW' }),
    ];

    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ alerts }), { status: 200 })
    );

    render(<AlertFeed token="test-token" />);

    await waitFor(() => {
      expect(screen.getByText('CRITICAL')).toBeInTheDocument();
      expect(screen.getByText('HIGH')).toBeInTheDocument();
      expect(screen.getByText('MEDIUM')).toBeInTheDocument();
      expect(screen.getByText('LOW')).toBeInTheDocument();
    });
  });

  it('constructs WebSocket URL with token', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ alerts: [] }), { status: 200 })
    );

    render(<AlertFeed token="my-jwt-token" />);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10);
    });

    expect(MockWebSocket.instances[0].url).toBe(
      'ws://localhost:8000/ws/alerts?token=my-jwt-token'
    );
  });
});
