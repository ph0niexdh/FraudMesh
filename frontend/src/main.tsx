import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import "./index.css";
import { Layout } from "./components/Layout";
import { LiveProvider } from "./hooks/live";
import { Dashboard } from "./pages/Dashboard";
import { CasesPage } from "./pages/Cases";
import { CaseInvestigation } from "./pages/CaseInvestigation";
import { EventExplorer } from "./pages/EventExplorer";
import { GraphPage } from "./pages/GraphPage";
import { PolicyCenter } from "./pages/PolicyCenter";
import { ModelMonitoring } from "./pages/ModelMonitoring";
import { StartupGate } from "./components/StartupGate";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <LiveProvider>
      <BrowserRouter>
        <StartupGate>
          <Routes>
            <Route element={<Layout />}>
              <Route index element={<Dashboard />} />
              <Route path="cases" element={<CasesPage />} />
              <Route path="cases/:caseId" element={<CaseInvestigation />} />
              <Route path="events" element={<EventExplorer />} />
              <Route path="graph" element={<GraphPage />} />
              <Route path="policies" element={<PolicyCenter />} />
              <Route path="models" element={<ModelMonitoring />} />
              <Route path="*" element={<div className="text-fg-muted">Page not found.</div>} />
            </Route>
          </Routes>
        </StartupGate>
      </BrowserRouter>
    </LiveProvider>
  </React.StrictMode>,
);
