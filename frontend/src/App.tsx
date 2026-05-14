import { useState } from 'react'
import Layout from './components/Layout'
import { DeviceInventoryTable } from './components/DeviceInventoryTable'
import NetworkTopologyGraph from './components/NetworkTopologyGraph'
import { AlertFeed } from './components/AlertFeed'
import ScanManagement from './components/ScanManagement'

const isDemoMode = import.meta.env.VITE_DEMO_MODE === 'true'

function App() {
  const [activeTab, setActiveTab] = useState('devices')

  // In demo mode, use a fake token; otherwise use real auth
  const token = isDemoMode ? 'demo-token' : ''

  return (
    <div className="flex flex-col min-h-screen">
      {isDemoMode && (
        <div className="bg-gray-900 text-gray-200 text-center text-sm py-1.5 px-4 font-medium tracking-wide">
          🔍 Demo Mode — Showing simulated OT network data
        </div>
      )}
      <Layout activeTab={activeTab} onTabChange={setActiveTab}>
        {activeTab === 'devices' && <DeviceInventoryTable />}
        {activeTab === 'topology' && <NetworkTopologyGraph />}
        {activeTab === 'alerts' && <AlertFeed token={token} />}
        {activeTab === 'scans' && <ScanManagement />}
      </Layout>
    </div>
  )
}

export default App
