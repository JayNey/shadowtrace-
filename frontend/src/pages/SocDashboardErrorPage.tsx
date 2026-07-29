/** Isolated error boundary page for `/dashboard` (ISSUE-085).

  Keeps SOC wall render failures from blanking the whole SPA — sibling
  routes under MainLayout remain reachable via the back link.
*/

import { isRouteErrorResponse, Link, useRouteError } from "react-router-dom";
import { Button, Typography } from "antd";
import "./SocDashboardPage.css";

export default function SocDashboardErrorPage() {
  const error = useRouteError();
  let detail = "大屏渲染异常，其他路由不受影响。";
  if (isRouteErrorResponse(error)) {
    detail = `${error.status} ${error.statusText}`;
  } else if (error instanceof Error) {
    detail = error.message;
  }

  return (
    <div className="soc-dark" data-testid="soc-dashboard-error">
      <div className="soc-header">
        <div>
          <h1 className="soc-brand">ShadowTrace SOC</h1>
          <p className="soc-subtitle">大屏暂不可用</p>
        </div>
        <Link to="/events" data-testid="soc-error-back">
          <Button type="primary">返回事件看板</Button>
        </Link>
      </div>
      <Typography.Paragraph style={{ color: "#ff7875" }}>{detail}</Typography.Paragraph>
    </div>
  );
}
