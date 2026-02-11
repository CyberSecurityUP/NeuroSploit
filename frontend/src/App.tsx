import { Routes, Route } from 'react-router-dom'
import Layout from './components/layout/Layout'
import HomePage from './pages/HomePage'
import NewScanPage from './pages/NewScanPage'
import ScanDetailsPage from './pages/ScanDetailsPage'
import AgentStatusPage from './pages/AgentStatusPage'
import TaskLibraryPage from './pages/TaskLibraryPage'
import RealtimeTaskPage from './pages/RealtimeTaskPage'
import ReportsPage from './pages/ReportsPage'
import ReportViewPage from './pages/ReportViewPage'
import SettingsPage from './pages/SettingsPage'
import SchedulerPage from './pages/SchedulerPage'
import AutoPentestPage from './pages/AutoPentestPage'
import VulnLabPage from './pages/VulnLabPage'
import TerminalAgentPage from './pages/TerminalAgentPage'
import SandboxDashboardPage from './pages/SandboxDashboardPage'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/auto" element={<AutoPentestPage />} />
        <Route path="/vuln-lab" element={<VulnLabPage />} />
        <Route path="/terminal" element={<TerminalAgentPage />} />
        <Route path="/scan/new" element={<NewScanPage />} />
        <Route path="/scan/:scanId" element={<ScanDetailsPage />} />
        <Route path="/agent/:agentId" element={<AgentStatusPage />} />
        <Route path="/tasks" element={<TaskLibraryPage />} />
        <Route path="/realtime" element={<RealtimeTaskPage />} />
        <Route path="/scheduler" element={<SchedulerPage />} />
        <Route path="/sandboxes" element={<SandboxDashboardPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/reports/:reportId" element={<ReportViewPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Routes>
    </Layout>
  )
}

export default App
