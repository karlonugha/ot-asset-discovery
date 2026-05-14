import { useState, useCallback } from 'react';
import { useDevices } from '../hooks/useDevices';
import type { DeviceFilters } from '../types/device';

const PAGE_SIZE = 50;

const defaultFilters: DeviceFilters = {
  vendor: '',
  model: '',
  protocol: '',
  subnet: '',
  risk_score_min: '',
  risk_score_max: '',
};

function getRiskColor(score: number): string {
  if (score >= 75) return 'text-red-700 bg-red-100';
  if (score >= 50) return 'text-orange-700 bg-orange-100';
  if (score >= 25) return 'text-yellow-700 bg-yellow-100';
  return 'text-green-700 bg-green-100';
}

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  return date.toLocaleString();
}

export function DeviceInventoryTable() {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState<DeviceFilters>(defaultFilters);
  const [pendingFilters, setPendingFilters] = useState<DeviceFilters>(defaultFilters);

  const { data, isLoading, isError, error } = useDevices({
    page,
    limit: PAGE_SIZE,
    filters,
  });

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  const handleFilterChange = useCallback(
    (field: keyof DeviceFilters, value: string) => {
      setPendingFilters((prev) => ({ ...prev, [field]: value }));
    },
    []
  );

  const applyFilters = useCallback(() => {
    setFilters(pendingFilters);
    setPage(1);
  }, [pendingFilters]);

  const clearFilters = useCallback(() => {
    setPendingFilters(defaultFilters);
    setFilters(defaultFilters);
    setPage(1);
  }, []);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter') {
        applyFilters();
      }
    },
    [applyFilters]
  );

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
        <h2 className="text-sm font-medium text-gray-700 mb-3">Filters</h2>
        <div className="grid grid-cols-1 tablet:grid-cols-2 desktop:grid-cols-3 gap-3">
          <div>
            <label htmlFor="filter-vendor" className="block text-xs font-medium text-gray-600 mb-1">
              Vendor
            </label>
            <input
              id="filter-vendor"
              type="text"
              placeholder="e.g. Siemens"
              value={pendingFilters.vendor}
              onChange={(e) => handleFilterChange('vendor', e.target.value)}
              onKeyDown={handleKeyDown}
              className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          <div>
            <label htmlFor="filter-model" className="block text-xs font-medium text-gray-600 mb-1">
              Model
            </label>
            <input
              id="filter-model"
              type="text"
              placeholder="e.g. S7-1200"
              value={pendingFilters.model}
              onChange={(e) => handleFilterChange('model', e.target.value)}
              onKeyDown={handleKeyDown}
              className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          <div>
            <label htmlFor="filter-protocol" className="block text-xs font-medium text-gray-600 mb-1">
              Protocol
            </label>
            <input
              id="filter-protocol"
              type="text"
              placeholder="e.g. modbus_tcp"
              value={pendingFilters.protocol}
              onChange={(e) => handleFilterChange('protocol', e.target.value)}
              onKeyDown={handleKeyDown}
              className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          <div>
            <label htmlFor="filter-subnet" className="block text-xs font-medium text-gray-600 mb-1">
              Subnet (CIDR)
            </label>
            <input
              id="filter-subnet"
              type="text"
              placeholder="e.g. 192.168.1.0/24"
              value={pendingFilters.subnet}
              onChange={(e) => handleFilterChange('subnet', e.target.value)}
              onKeyDown={handleKeyDown}
              className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          <div>
            <label htmlFor="filter-risk-min" className="block text-xs font-medium text-gray-600 mb-1">
              Risk Score Min
            </label>
            <input
              id="filter-risk-min"
              type="number"
              min="0"
              max="100"
              placeholder="0"
              value={pendingFilters.risk_score_min}
              onChange={(e) => handleFilterChange('risk_score_min', e.target.value)}
              onKeyDown={handleKeyDown}
              className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          <div>
            <label htmlFor="filter-risk-max" className="block text-xs font-medium text-gray-600 mb-1">
              Risk Score Max
            </label>
            <input
              id="filter-risk-max"
              type="number"
              min="0"
              max="100"
              placeholder="100"
              value={pendingFilters.risk_score_max}
              onChange={(e) => handleFilterChange('risk_score_max', e.target.value)}
              onKeyDown={handleKeyDown}
              className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
        </div>
        <div className="flex gap-2 mt-3">
          <button
            onClick={applyFilters}
            className="px-4 py-1.5 text-sm font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            Apply Filters
          </button>
          <button
            onClick={clearFilters}
            className="px-4 py-1.5 text-sm font-medium text-gray-700 bg-gray-100 rounded-md hover:bg-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-400"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        {isLoading && (
          <div className="p-8 text-center text-gray-500">Loading devices...</div>
        )}

        {isError && (
          <div className="p-8 text-center text-red-600">
            Error loading devices: {error instanceof Error ? error.message : 'Unknown error'}
          </div>
        )}

        {data && (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-4 py-3 font-medium text-gray-700 whitespace-nowrap">IP Address</th>
                    <th className="px-4 py-3 font-medium text-gray-700 whitespace-nowrap">MAC Address</th>
                    <th className="px-4 py-3 font-medium text-gray-700 whitespace-nowrap">Vendor</th>
                    <th className="px-4 py-3 font-medium text-gray-700 whitespace-nowrap">Model</th>
                    <th className="px-4 py-3 font-medium text-gray-700 whitespace-nowrap">Firmware</th>
                    <th className="px-4 py-3 font-medium text-gray-700 whitespace-nowrap">Protocols</th>
                    <th className="px-4 py-3 font-medium text-gray-700 whitespace-nowrap">Risk Score</th>
                    <th className="px-4 py-3 font-medium text-gray-700 whitespace-nowrap">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {data.devices.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                        No devices found matching the current filters.
                      </td>
                    </tr>
                  ) : (
                    data.devices.map((device) => (
                      <tr key={device.id} className="hover:bg-gray-50">
                        <td className="px-4 py-2.5 font-mono text-xs whitespace-nowrap">
                          {device.ip_address}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-xs whitespace-nowrap">
                          {device.mac_address}
                        </td>
                        <td className="px-4 py-2.5 whitespace-nowrap">
                          {device.vendor ?? <span className="text-gray-400">—</span>}
                        </td>
                        <td className="px-4 py-2.5 whitespace-nowrap">
                          {device.model ?? <span className="text-gray-400">—</span>}
                        </td>
                        <td className="px-4 py-2.5 whitespace-nowrap">
                          {device.firmware_version ?? <span className="text-gray-400">—</span>}
                        </td>
                        <td className="px-4 py-2.5">
                          <div className="flex flex-wrap gap-1">
                            {device.protocols.length > 0 ? (
                              device.protocols.map((proto) => (
                                <span
                                  key={proto}
                                  className="inline-block px-1.5 py-0.5 text-xs bg-blue-100 text-blue-700 rounded"
                                >
                                  {proto}
                                </span>
                              ))
                            ) : (
                              <span className="text-gray-400">—</span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-2.5 whitespace-nowrap">
                          <span
                            className={`inline-block px-2 py-0.5 text-xs font-medium rounded ${getRiskColor(device.risk_score)}`}
                          >
                            {device.risk_score}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-xs text-gray-600 whitespace-nowrap">
                          {formatTimestamp(device.last_seen)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 bg-gray-50">
              <div className="text-xs text-gray-600">
                Showing {data.devices.length > 0 ? data.offset + 1 : 0}–
                {Math.min(data.offset + data.limit, data.total)} of {data.total} devices
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage(1)}
                  disabled={page === 1}
                  aria-label="First page"
                  className="px-2 py-1 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  First
                </button>
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  aria-label="Previous page"
                  className="px-2 py-1 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Prev
                </button>
                <span className="text-xs text-gray-700">
                  Page {page} of {totalPages || 1}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  aria-label="Next page"
                  className="px-2 py-1 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                </button>
                <button
                  onClick={() => setPage(totalPages)}
                  disabled={page >= totalPages}
                  aria-label="Last page"
                  className="px-2 py-1 text-xs font-medium text-gray-700 bg-white border border-gray-300 rounded hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Last
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
