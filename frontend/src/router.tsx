/** Application router (ISSUE-067). */

import { createBrowserRouter } from "react-router-dom";
import MainLayout from "./layouts/MainLayout";
import EventListPage from "./pages/EventListPage";
import EventDetailPage from "./pages/EventDetailPage";
import ApprovalPage from "./pages/ApprovalPage";
import ToolAuditPage from "./pages/ToolAuditPage";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <MainLayout />,
    children: [
      { index: true, element: <EventListPage /> },
      { path: "events", element: <EventListPage /> },
      { path: "events/:eventId", element: <EventDetailPage /> },
      { path: "approvals", element: <ApprovalPage /> },
      { path: "tools-audit", element: <ToolAuditPage /> },
    ],
  },
]);
