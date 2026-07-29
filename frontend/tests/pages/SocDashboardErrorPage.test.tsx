/** SocDashboardErrorPage — route errorElement isolation (ISSUE-085). */

import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import SocDashboardErrorPage from "../../src/pages/SocDashboardErrorPage";

function Boom(): never {
  throw new Error("dashboard render boom");
}

describe("SocDashboardErrorPage", () => {
  it("catches dashboard render errors and links back to events", async () => {
    const router = createMemoryRouter(
      [
        {
          path: "/dashboard",
          element: <Boom />,
          errorElement: <SocDashboardErrorPage />,
        },
        { path: "/events", element: <div>events-ok</div> },
      ],
      { initialEntries: ["/dashboard"] },
    );

    render(<RouterProvider router={router} />);

    expect(await screen.findByTestId("soc-dashboard-error")).toBeInTheDocument();
    expect(screen.getByText(/dashboard render boom/i)).toBeInTheDocument();
    expect(screen.getByTestId("soc-error-back")).toHaveAttribute("href", "/events");
    // Sibling route remains registered (not unmounted from the router tree).
    expect(router.routes.some((r) => r.path === "/events")).toBe(true);
  });
});
