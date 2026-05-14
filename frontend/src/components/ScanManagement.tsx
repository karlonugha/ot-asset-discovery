import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchScansDemo, fetchScanHistoryDemo } from '../data/demoApi'

const isDemoMode = import.meta.env.VITE_DEMO_MODE === 'true'

interface ScanJob {
  id: string
  name: string
  schedule: string | null
  target_subnet: string | null
  active_probing_enabled: boolean
  status: string
  started_at: string | null
  completed_at: string | null
  devices_discovered: number
  new_devices: number
  alerts_generated: number
  failure_reason: string | null
  created_at: string
  updated_at: string
}

interface ScanJobFormData {
  name: string
  schedule: string
  target_subnet: string
  active_probing_enabled: boolean
}

interface ScanHistoryItem {
  id: string
  scan_job_id: string
  status: string
  started_at: string
  completed_at: string | null
  devices_discovered: number
  new_devices: number
  alerts_generated: number
  failure_reason: string | null
}

interface ScanHistoryResponse {
  items: ScanHistoryItem[]
  total: number
  page: number
  page_size: number
}

const STATUS_STYLES: Record<string, string> = {
  scheduled: 'bg-gray-100 text-gray-700',
  running: 'bg-blue-100 text-blue-700',
  completed: 'bg-green-100 text-green-700',
  failed: 'bg-red-100 text-red-700',
  skipped: 'bg-yellow-100 text-yellow-700',
}

async function fetchScans(): Promise<ScanJob[]> {
  if (isDemoMode) {
    return fetchScansDemo()
  }
  const res = await fetch('/api/scans')
  if (!res.ok) throw new Error(`Failed: ${res.status}`)
  return res.json()
}

async function fetchHistory(scanId: string, page = 1, pageSize = 20): Promise<ScanHistoryResponse> {
  if (isDemoMode) {
    return fetchScanHistoryDemo(scanId, page, pageSize)
  }
  const res = await fetch(`/api/scans/${scanId}/history?page=${page}&page_size=${pageSize}`)
  if (!res.ok) throw new Error(`Failed: ${res.status}`)
  return res.json()
}

function ScanJobForm({
  onSubmit,
  onCancel,
  initialData,
}: {
  onSubmit: (data: ScanJobFormData) => void
  onCancel: () => void
  initialData?: ScanJobFormData
}) {
  const [name, setName] = useState(initialData?.name ?? '')
  const [schedule, setSchedule] = useState(initialData?.schedule ?? '')
  const [targetSubnet, setTargetSubnet] = useState(initialData?.target_subnet ?? '')
  const [activeProbing, setActiveProbing] = useState(initialData?.active_probing_enabled ?? false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit({
      name,
      schedule,
      target_subnet: targetSubnet,
      active_probing_enabled: activeProbing,
    })
  }

  return (
    <form onSubmit={handleSubmit} className="bg-white rounded-lg border border-gray-200 p-4 space-y-4">
      <div>
        <label htmlFor="scan-name" className="block text-sm font-medium text-gray-700 mb-1">
          Name
        </label>
        <input
          id="scan-name"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          required
        />
      </div>
      <div>
        <label htmlFor="scan-schedule" className="block text-sm font-medium text-gray-700 mb-1">
          Cron Schedule
        </label>
        <input
          id="scan-schedule"
          type="text"
          value={schedule}
          onChange={(e) => setSchedule(e.target.value)}
          placeholder="e.g. */30 * * * *"
          className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>
      <div>
        <label htmlFor="scan-subnet" className="block text-sm font-medium text-gray-700 mb-1">
          Target Subnet (CIDR)
        </label>
        <input
          id="scan-subnet"
          type="text"
          value={targetSubnet}
          onChange={(e) => setTargetSubnet(e.target.value)}
          placeholder="e.g. 192.168.1.0/24"
          className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>
      <div className="flex items-center gap-2">
        <input
          id="scan-active-probing"
          type="checkbox"
          checked={activeProbing}
          onChange={(e) => setActiveProbing(e.target.checked)}
          className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
        />
        <label htmlFor="scan-active-probing" className="text-sm text-gray-700">
          Enable active probing
        </label>
      </div>
      <div className="flex gap-2">
        <button
          type="submit"
          className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700"
        >
          {initialData ? 'Update' : 'Create'}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200"
        >
          Cancel
        </button>
      </div>
    </form>
  )
}

function ScanHistoryView({ scanId, scanName, onClose }: { scanId: string; scanName: string; onClose: () => void }) {
  const [page, setPage] = useState(1)
  const pageSize = 20

  const { data, isLoading } = useQuery({
    queryKey: ['scan-history', scanId, page],
    queryFn: () => fetchHistory(scanId, page, pageSize),
  })

  const totalPages = data ? Math.ceil(data.total / pageSize) : 0

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-900">History: {scanName}</h3>
        <button onClick={onClose} className="text-xs text-gray-500 hover:text-gray-700">
          Close
        </button>
      </div>
      {isLoading && <p className="text-sm text-gray-500">Loading history...</p>}
      {data && data.items.length === 0 && (
        <p className="text-sm text-gray-500">No history available.</p>
      )}
      {data && data.items.length > 0 && (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-2 py-1.5 text-left font-medium text-gray-600">Status</th>
                  <th className="px-2 py-1.5 text-left font-medium text-gray-600">Started</th>
                  <th className="px-2 py-1.5 text-left font-medium text-gray-600">Devices</th>
                  <th className="px-2 py-1.5 text-left font-medium text-gray-600">New</th>
                  <th className="px-2 py-1.5 text-left font-medium text-gray-600">Alerts</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {data.items.map((item) => (
                  <tr key={item.id}>
                    <td className="px-2 py-1.5">
                      <span className={`inline-flex px-1.5 py-0.5 rounded text-xs font-medium ${STATUS_STYLES[item.status] ?? ''}`}>
                        {item.status}
                      </span>
                    </td>
                    <td className="px-2 py-1.5 text-gray-600">{new Date(item.started_at).toLocaleString()}</td>
                    <td className="px-2 py-1.5 text-gray-900">{item.devices_discovered}</td>
                    <td className="px-2 py-1.5 text-gray-900">{item.new_devices}</td>
                    <td className="px-2 py-1.5 text-gray-900">{item.alerts_generated}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-2 border-t border-gray-100">
              <p className="text-xs text-gray-500">
                Page {page} of {totalPages} ({data.total} total)
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1}
                  className="rounded border border-gray-300 px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  className="rounded border border-gray-300 px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default function ScanManagement() {
  const queryClient = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [editingScan, setEditingScan] = useState<ScanJob | null>(null)
  const [historyView, setHistoryView] = useState<{ id: string; name: string } | null>(null)
  const [demoStatus, setDemoStatus] = useState<string | null>(null)

  const { data: scans, isLoading, isError } = useQuery({
    queryKey: ['scans'],
    queryFn: fetchScans,
  })

  const createMutation = useMutation({
    mutationFn: async (data: ScanJobFormData) => {
      if (isDemoMode) {
        // Simulate creation in demo mode
        setDemoStatus(`Scan "${data.name}" created (simulated)`)
        setTimeout(() => setDemoStatus(null), 3000)
        return
      }
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      if (!res.ok) throw new Error('Failed to create scan')
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setShowForm(false)
    },
  })

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: ScanJobFormData }) => {
      if (isDemoMode) {
        setDemoStatus(`Scan "${data.name}" updated (simulated)`)
        setTimeout(() => setDemoStatus(null), 3000)
        return
      }
      const res = await fetch(`/api/scans/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      if (!res.ok) throw new Error('Failed to update scan')
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setEditingScan(null)
    },
  })

  const triggerMutation = useMutation({
    mutationFn: async (id: string) => {
      if (isDemoMode) {
        const scan = scans?.find((s) => s.id === id)
        setDemoStatus(`Scan "${scan?.name ?? id}" triggered (simulated)`)
        setTimeout(() => setDemoStatus(null), 3000)
        return
      }
      const res = await fetch(`/api/scans/${id}/trigger`, { method: 'POST' })
      if (!res.ok) throw new Error('Failed to trigger scan')
      return res.json()
    },
    onSuccess: () => {
      if (!isDemoMode) {
        queryClient.invalidateQueries({ queryKey: ['scans'] })
      }
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      if (isDemoMode) {
        setDemoStatus('Scan deleted (simulated)')
        setTimeout(() => setDemoStatus(null), 3000)
        return
      }
      const res = await fetch(`/api/scans/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('Failed to delete scan')
      return res.json()
    },
    onSuccess: () => {
      if (!isDemoMode) {
        queryClient.invalidateQueries({ queryKey: ['scans'] })
      }
    },
  })

  const handleDelete = (id: string) => {
    if (window.confirm('Are you sure you want to delete this scan schedule?')) {
      deleteMutation.mutate(id)
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <h2 className="text-lg font-semibold text-gray-900">Scan Management</h2>
        <p className="text-gray-500">Loading scans...</p>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="space-y-4">
        <h2 className="text-lg font-semibold text-gray-900">Scan Management</h2>
        <p className="text-red-600">Failed to load scan schedules.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col tablet:flex-row tablet:items-center tablet:justify-between gap-3">
        <h2 className="text-lg font-semibold text-gray-900">Scan Management</h2>
        {!showForm && !editingScan && (
          <button
            onClick={() => setShowForm(true)}
            className="inline-flex items-center px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 w-full tablet:w-auto justify-center"
          >
            New Scan Schedule
          </button>
        )}
      </div>

      {/* Demo status toast */}
      {demoStatus && (
        <div className="bg-blue-50 border border-blue-200 text-blue-800 text-sm px-4 py-2 rounded-md">
          {demoStatus}
        </div>
      )}

      {showForm && (
        <ScanJobForm
          onSubmit={(data) => createMutation.mutate(data)}
          onCancel={() => setShowForm(false)}
        />
      )}

      {editingScan && (
        <ScanJobForm
          initialData={{
            name: editingScan.name,
            schedule: editingScan.schedule ?? '',
            target_subnet: editingScan.target_subnet ?? '',
            active_probing_enabled: editingScan.active_probing_enabled,
          }}
          onSubmit={(data) => updateMutation.mutate({ id: editingScan.id, data })}
          onCancel={() => setEditingScan(null)}
        />
      )}

      {historyView && (
        <ScanHistoryView
          scanId={historyView.id}
          scanName={historyView.name}
          onClose={() => setHistoryView(null)}
        />
      )}

      {scans && scans.length === 0 && !showForm && (
        <p className="text-gray-500 text-sm">No scan schedules configured. Create one to get started.</p>
      )}

      {scans && scans.length > 0 && (
        <div className="grid gap-4 grid-cols-1 desktop:grid-cols-2">
          {scans.map((scan) => (
            <div
              key={scan.id}
              className="bg-white rounded-lg border border-gray-200 p-4 space-y-3"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <h3 className="text-sm font-semibold text-gray-900 truncate">{scan.name}</h3>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {scan.target_subnet ?? 'All subnets'}
                    {scan.schedule && ` • Cron: ${scan.schedule}`}
                  </p>
                </div>
                <span
                  className={`inline-flex px-2 py-0.5 text-xs font-medium rounded-full whitespace-nowrap ${STATUS_STYLES[scan.status] ?? 'bg-gray-100 text-gray-700'}`}
                >
                  {scan.status}
                </span>
              </div>

              {(scan.devices_discovered > 0 || scan.new_devices > 0 || scan.alerts_generated > 0) && (
                <p className="text-xs text-gray-600">
                  Discovered: {scan.devices_discovered} devices • {scan.new_devices} new • {scan.alerts_generated} alerts
                </p>
              )}

              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => triggerMutation.mutate(scan.id)}
                  className="px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 rounded hover:bg-blue-100"
                >
                  ▶ Run
                </button>
                <button
                  onClick={() => setHistoryView({ id: scan.id, name: scan.name })}
                  className="px-3 py-1.5 text-xs font-medium text-gray-700 bg-gray-50 rounded hover:bg-gray-100"
                >
                  History
                </button>
                <button
                  onClick={() => setEditingScan(scan)}
                  className="px-3 py-1.5 text-xs font-medium text-gray-700 bg-gray-50 rounded hover:bg-gray-100"
                >
                  Edit
                </button>
                <button
                  onClick={() => handleDelete(scan.id)}
                  className="px-3 py-1.5 text-xs font-medium text-red-700 bg-red-50 rounded hover:bg-red-100"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
