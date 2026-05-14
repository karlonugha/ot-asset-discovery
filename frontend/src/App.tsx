import { useState } from 'react'
import Layout from './components/Layout'
import { DeviceInventoryTable } from './components/DeviceInventoryTable'
import NetworkTopologyGraph from './components/NetworkTopologyGraph'
import { AlertFeed } from './components/AlertFeed'
import ScanManagement from './components/ScanManagement'

function App() {
  const [activeTab, setActiveTab] = useState('devices')

  // TODO: Replace with actual auth token from login flow
  const token = ''

  return (
    <Layout activeTab={activeTab} onTabChange={setActiveTab}>
      {activeTab === 'devices' && <DeviceInventoryTable />}
      {activeTab === 'topology' && <NetworkTopologyGraph />}
      {activeTab === 'alerts' && <AlertFeed token={token} />}
      {activeTab === 'scans' && <ScanManagement />}
    </Layout>
  )
}

export default App
