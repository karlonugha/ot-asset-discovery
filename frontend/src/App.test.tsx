import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import App from './App'

// Mock NetworkTopologyGraph to avoid aframe dependency in test environment
vi.mock('./components/NetworkTopologyGraph', () => ({
  default: () => <div data-testid="topology-graph">Topology Graph Mock</div>,
}))

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('App', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      () => new Promise(() => {})
    )
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders the application header', () => {
    render(<App />, { wrapper: createWrapper() })
    expect(screen.getByText('OT Asset Discovery')).toBeInTheDocument()
  })
})
