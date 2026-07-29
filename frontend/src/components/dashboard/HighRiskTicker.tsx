/** HighRiskTicker — scrolling high/critical event feed (ISSUE-085). */

import { Typography } from "antd";
import { severityColor, severityLabel } from "./constants";

export interface TickerItem {
  event_id: string;
  title?: string;
  severity: string;
  event_type?: string;
  created_at?: string;
}

export default function HighRiskTicker({ items }: { items: TickerItem[] }) {
  const highRisk = items.filter(
    (i) => i.severity === "high" || i.severity === "critical",
  );

  return (
    <div className="soc-panel soc-ticker" data-testid="high-risk-ticker">
      <Typography.Title level={5} className="soc-panel-title">
        高风险事件滚动
      </Typography.Title>
      {highRisk.length === 0 ? (
        <Typography.Text type="secondary">暂无高/紧急事件</Typography.Text>
      ) : (
        <div className="soc-ticker-track">
          <div className="soc-ticker-scroll">
            {[...highRisk, ...highRisk].map((item, idx) => (
              <span className="soc-ticker-item" key={`${item.event_id}-${idx}`}>
                <span
                  className="soc-ticker-sev"
                  style={{ color: severityColor(item.severity) }}
                >
                  [{severityLabel(item.severity)}]
                </span>{" "}
                <span className="soc-ticker-id">{item.event_id}</span>
                {item.title ? ` — ${item.title}` : ""}
                {item.event_type ? ` · ${item.event_type}` : ""}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
