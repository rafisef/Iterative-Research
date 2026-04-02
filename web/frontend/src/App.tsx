import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { PageShell } from './components/layout/PageShell';
import { DashboardPage } from './pages/DashboardPage';
import { NewExperimentPage } from './pages/NewExperimentPage';
import { RunDetailPage } from './pages/RunDetailPage';
import { ConfigPage } from './pages/ConfigPage';
import { ToolsPage } from './pages/ToolsPage';

export default function App() {
  return (
    <BrowserRouter>
      <PageShell>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/new" element={<NewExperimentPage />} />
          <Route path="/runs/:runId" element={<RunDetailPage />} />
          <Route path="/config" element={<ConfigPage />} />
          <Route path="/tools" element={<ToolsPage />} />
        </Routes>
      </PageShell>
    </BrowserRouter>
  );
}
