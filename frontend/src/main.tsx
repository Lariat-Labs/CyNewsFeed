import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "./index.css";
import Layout from "./components/Layout";
import Feed from "./pages/Feed";
import Dashboard from "./pages/Dashboard";
import Rules from "./pages/Rules";
import Sources from "./pages/Sources";
import Digests from "./pages/Digests";
import Activity from "./pages/Activity";
import ChatPage from "./pages/Chat";
import Settings from "./pages/Settings";
import IOCs from "./pages/IOCs";
import Events from "./pages/Events";
import AISecurity from "./pages/AISecurity";

// Apply the saved theme before first paint.
try {
  document.documentElement.dataset.theme = localStorage.getItem("theme") || "dark";
} catch {
  document.documentElement.dataset.theme = "dark";
}

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 30_000, refetchOnWindowFocus: true, retry: 1 } },
});

const router = createBrowserRouter([
  {
    element: <Layout />,
    children: [
      { path: "/", element: <Feed /> },
      { path: "/dashboard", element: <Dashboard /> },
      { path: "/rules", element: <Rules /> },
      { path: "/sources", element: <Sources /> },
      { path: "/digests", element: <Digests /> },
      { path: "/digests/weekly", element: <Digests /> },
      { path: "/digests/:date", element: <Digests /> },
      { path: "/activity", element: <Activity /> },
      { path: "/chat", element: <ChatPage /> },
      { path: "/chat/:id", element: <ChatPage /> },
      { path: "/settings", element: <Settings /> },
      { path: "/iocs", element: <IOCs /> },
      { path: "/events", element: <Events /> },
      { path: "/ai-security", element: <AISecurity /> },
      { path: "/digests/weekly/:reportId", element: <Digests /> },
      { path: "*", element: <Feed /> },
    ],
  },
]);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
