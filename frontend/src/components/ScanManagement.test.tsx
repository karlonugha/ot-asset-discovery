import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import ScanManagement from './ScanManagement'

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

const mockScans = [
  {
    id: '1',
    name: 'Nightly OT Scan',
    schedule: '0 0 * * *',
    target_subnet: '192.168.1.0/24',
    active_probing_enabled: true,
    status: 'completed',
    started_at: '2024-01-15T00:00:00Z',
    completed_at: '2024-01-15T00:05:00Z',
    devices_discovered: 12,
    new_devices: 2,
    alerts_generated: 3,
    failure_reason: null,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-15T00:05:00Z',
  },
  {
    id: '2',
    name: 'Weekly Full Scan',
    schedule: '0 2 * * 0',
    target_subnet: '10.0.0.0/16',
    active_probing_enabled: false,
    status: 'scheduled',
    started_at: null,
    completed_at: null,
    devices_discovered: 0,
    new_devices: 0,
    alerts_generated: 0,
    failure_reason: null,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
]

const mockHistory = {
  items: [
    {
      id: 'h1',
      scan_job_id: '1',
      status: 'completed',
      started_at: '2024-01-15T00:00:00Z',
      completed_at: '2024-01-15T00:05:00Z',
      devices_discovered: 12,
      new_devices: 2,
      alerts_generated: 3,
      failure_reason: null,
    },
    {
      id: 'h2',
      scan_job_id: '1',
      status: 'completed',
      started_at: '2024-01-14T00:00:00Z',
      completed_at: '2024-01-14T00:04:30Z',
      devices_discovered: 10,
      new_devices: 0,
      alerts_generated: 1,
      failure_reason: null,
    },
  ],
  total: 2,
  page: 1,
  page_size: 20,
}

beforeEach(() => {
  vi.restoreAllMocks()
})

describe('ScanManagement', () => {
  it('renders scan list when data is loaded', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockScans),
    } as Response)

    render(<ScanManagement />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText('Nightly OT Scan')).toBeInTheDocument()
    })
    expect(screen.getByText('Weekly Full Scan')).toBeInTheDocument()
    expect(screen.getByText('Scan Management')).toBeInTheDocument()
  })

  it('shows loading state initially', () => {
    vi.spyOn(globalThis, 'fetch').mockReturnValueOnce(new Promise(() => {}))

    render(<ScanManagement />, { wrapper: createWrapper() })

    expect(screen.getByText('Loading scans...')).toBeInTheDocument()
  })

  it('shows error state when fetch fails', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: false,
      status: 500,
    } as Response)

    render(<ScanManagement />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText('Failed to load scan schedules.')).toBeInTheDocument()
    })
  })

  it('shows create form when "New Scan Schedule" is clicked', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockScans),
    } as Response)

    render(<ScanManagement />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText('Nightly OT Scan')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('New Scan Schedule'))

    expect(screen.getByLabelText('Name')).toBeInTheDocument()
    expect(screen.getByLabelText('Cron Schedule')).toBeInTheDocument()
    expect(screen.getByLabelText('Target Subnet (CIDR)')).toBeInTheDocument()
    expect(screen.getByLabelText('Enable active probing')).toBeInTheDocument()
  })

  it('submits create form and calls API', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    // Initial load
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([]),
    } as Response)

    render(<ScanManagement />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText('No scan schedules configured. Create one to get started.')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText('New Scan Schedule'))

    // Fill form
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Test Scan' } })
    fireEvent.change(screen.getByLabelText('Cron Schedule'), { target: { value: '*/10 * * * *' } })
    fireEvent.change(screen.getByLabelText('Target Subnet (CIDR)'), { target: { value: '10.0.0.0/24' } })

    // Mock create response
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ id: '3', name: 'Test Scan', schedule: '*/10 * * * *', target_subnet: '10.0.0.0/24', active_probing_enabled: false, status: 'scheduled', started_at: null, completed_at: null, devices_discovered: 0, new_devices: 0, alerts_generated: 0, failure_reason: null, created_at: '2024-01-16T00:00:00Z', updated_at: '2024-01-16T00:00:00Z' }),
    } as Response)

    // Mock refetch
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([{ id: '3', name: 'Test Scan', schedule: '*/10 * * * *', target_subnet: '10.0.0.0/24', active_probing_enabled: false, status: 'scheduled', started_at: null, completed_at: null, devices_discovered: 0, new_devices: 0, alerts_generated: 0, failure_reason: null, created_at: '2024-01-16T00:00:00Z', updated_at: '2024-01-16T00:00:00Z' }]),
    } as Response)

    fireEvent.click(screen.getByText('Create'))

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/api/scans', expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          name: 'Test Scan',
          schedule: '*/10 * * * *',
          target_subnet: '10.0.0.0/24',
          active_probing_enabled: false,
        }),
      }))
    })
  })

  it('triggers manual scan when Run button is clicked', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockScans),
    } as Response)

    render(<ScanManagement />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText('Nightly OT Scan')).toBeInTheDocument()
    })

    // Mock trigger response
    fetchMock.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({}) } as Response)
    // Mock refetch
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockScans),
    } as Response)

    const runButtons = screen.getAllByText('▶ Run')
    fireEvent.click(runButtons[0])

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/api/scans/1/trigger', { method: 'POST' })
    })
  })

  it('shows scan history when History button is clicked', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockScans),
    } as Response)

    render(<ScanManagement />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText('Nightly OT Scan')).toBeInTheDocument()
    })

    // Mock history response
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockHistory),
    } as Response)

    const historyButtons = screen.getAllByText('History')
    fireEvent.click(historyButtons[0])

    await waitFor(() => {
      expect(screen.getByText('History: Nightly OT Scan')).toBeInTheDocument()
    })
  })

  it('deletes a scan when Delete is confirmed', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockScans),
    } as Response)

    vi.spyOn(window, 'confirm').mockReturnValue(true)

    render(<ScanManagement />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText('Nightly OT Scan')).toBeInTheDocument()
    })

    // Mock delete response
    fetchMock.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({}) } as Response)
    // Mock refetch
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([mockScans[1]]),
    } as Response)

    const deleteButtons = screen.getAllByText('Delete')
    fireEvent.click(deleteButtons[0])

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/api/scans/1', { method: 'DELETE' })
    })
  })

  it('displays status badges correctly', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockScans),
    } as Response)

    render(<ScanManagement />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText('completed')).toBeInTheDocument()
      expect(screen.getByText('scheduled')).toBeInTheDocument()
    })
  })

  it('shows scan result details for completed scans', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockScans),
    } as Response)

    render(<ScanManagement />, { wrapper: createWrapper() })

    await waitFor(() => {
      expect(screen.getByText(/Discovered:/)).toBeInTheDocument()
    })
    // The text is split across elements, so check individual parts
    expect(screen.getByText(/12 devices/)).toBeInTheDocument()
  })
})

