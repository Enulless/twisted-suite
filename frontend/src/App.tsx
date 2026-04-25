import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Toaster } from "sonner";
import { CommandPalette } from "./components/CommandPalette";
import { Layout } from "./components/Layout";
import { EngagementListPage } from "./pages/EngagementList";
import { EngagementWizardPage } from "./pages/EngagementWizard";
import { EngagementLayout } from "./layouts/EngagementLayout";
import { EngagementOverviewSubPage } from "./pages/engagement/EngagementOverviewSub";
import { ScopePage } from "./pages/engagement/Scope";
import { ToolingPage } from "./pages/engagement/Tooling";
import { EngagementProceduresPage } from "./pages/engagement/Procedures";
import { AssetsPage } from "./pages/engagement/Assets";
import { FindingsPage } from "./pages/engagement/Findings";
import { FindingDetailPage } from "./pages/engagement/FindingDetail";
import { RunsPage } from "./pages/engagement/Runs";
import { ReportPage } from "./pages/engagement/Report";
import { WorkersPage } from "./pages/Workers";
import { LabsPage } from "./pages/Labs";
import { ProceduresPage } from "./pages/Procedures";
import { TrainingIndexPage } from "./pages/TrainingIndex";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <CommandPalette />
        <Toaster theme="dark" position="bottom-right" richColors />
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<EngagementListPage />} />
            <Route path="engagements" element={<Navigate to="/" replace />} />
            <Route path="engagements/new" element={<EngagementWizardPage />} />
            <Route path="engagements/:id" element={<EngagementLayout />}>
              <Route index element={<EngagementOverviewSubPage />} />
              <Route path="scope" element={<ScopePage />} />
              <Route path="tooling" element={<ToolingPage />} />
              <Route path="procedures" element={<EngagementProceduresPage />} />
              <Route path="assets" element={<AssetsPage />} />
              <Route path="findings" element={<FindingsPage />} />
              <Route path="findings/:fid" element={<FindingDetailPage />} />
              <Route path="runs" element={<RunsPage />} />
              <Route path="report" element={<ReportPage />} />
            </Route>
            <Route path="workers" element={<WorkersPage />} />
            <Route path="labs" element={<LabsPage />} />
            <Route path="procedures" element={<ProceduresPage />} />
            <Route path="training" element={<TrainingIndexPage />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center py-24">
      <h2 className="text-3xl font-semibold">Not found</h2>
      <p className="mt-2 text-muted-foreground">
        That page doesn't exist (yet).
      </p>
    </div>
  );
}
