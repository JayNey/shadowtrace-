/** SocDashboardPage — SOC overview wall (ISSUE-085).

  Dark theme (``.soc-dark``), fullscreen toggle, 30s polling + socket
  global-room incremental updates for ticker / refresh triggers.
*/

import { useCallback, useEffect, useRef, useState } from "react";
import { Button, Col, Row, Space, Typography, message } from "antd";
import {
  FullscreenExitOutlined,
  FullscreenOutlined,
  ReloadOutlined,
} from "@ant-design/icons";
import apiClient from "../services/apiClient";
import { listEvents } from "../services/eventApi";
import { socketClient } from "../services/socketClient";
import type { StatsResponse } from "../types/stats";
import StatCardGrid from "../components/dashboard/StatCardGrid";
import SeverityPieChart from "../components/dashboard/SeverityPieChart";
import EventTrendChart from "../components/dashboard/EventTrendChart";
import HighRiskTicker, {
  type TickerItem,
} from "../components/dashboard/HighRiskTicker";
import "./SocDashboardPage.css";

const REFRESH_MS = 30_000;

function getStats() {
  return apiClient.get<StatsResponse>("/stats");
}

export default function SocDashboardPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [ticker, setTicker] = useState<TickerItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const refreshTimer = useRef<number | undefined>(undefined);

  const loadStats = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getStats();
      setStats(res.data);
    } catch {
      // apiClient already toasts; keep last good snapshot.
    } finally {
      setLoading(false);
    }
  }, []);

  const loadHighRiskSeed = useCallback(async () => {
    try {
      const [high, critical] = await Promise.all([
        listEvents({ severity: "high", page: 1, page_size: 10 }),
        listEvents({ severity: "critical", page: 1, page_size: 10 }),
      ]);
      const merged: TickerItem[] = [
        ...critical.data.items,
        ...high.data.items,
      ].map((item) => ({
        event_id: item.event_id,
        title: item.title,
        severity: item.severity,
        event_type: item.event_type,
        created_at: item.created_at ?? undefined,
      }));
      // Dedup by event_id, critical first.
      const seen = new Set<string>();
      const unique = merged.filter((item) => {
        if (seen.has(item.event_id)) return false;
        seen.add(item.event_id);
        return true;
      });
      setTicker(unique.slice(0, 30));
    } catch {
      // optional seed — socket increments still work
    }
  }, []);

  const refreshAll = useCallback(async () => {
    await Promise.all([loadStats(), loadHighRiskSeed()]);
  }, [loadStats, loadHighRiskSeed]);

  useEffect(() => {
    void refreshAll();
    refreshTimer.current = window.setInterval(() => {
      void refreshAll();
    }, REFRESH_MS);
    return () => {
      if (refreshTimer.current != null) {
        window.clearInterval(refreshTimer.current);
      }
    };
  }, [refreshAll]);

  // Socket global room: new high-risk events update ticker; any create refreshes stats.
  useEffect(() => {
    socketClient.connect();
    const unsub = socketClient.onEvent((evt) => {
      if (evt.type === "event_created") {
        const sev = (evt.payload.severity ?? "").toLowerCase();
        if (sev === "high" || sev === "critical") {
          setTicker((prev) => {
            if (prev.some((i) => i.event_id === evt.event_id)) return prev;
            const next: TickerItem = {
              event_id: evt.event_id,
              severity: sev,
              event_type: evt.payload.event_type,
              created_at: evt.payload.created_at,
            };
            return [next, ...prev].slice(0, 40);
          });
        }
        // Soft refresh stats soon (debounced by timer; also bump immediately).
        void loadStats();
      }
      if (evt.type === "state_change" || evt.type === "writeback_updated") {
        void loadStats();
      }
    });
    return () => {
      unsub();
    };
  }, [loadStats]);

  const toggleFullscreen = async () => {
    const el = rootRef.current;
    if (!el) return;
    try {
      if (!document.fullscreenElement) {
        await el.requestFullscreen();
        setFullscreen(true);
      } else {
        await document.exitFullscreen();
        setFullscreen(false);
      }
    } catch {
      message.warning("当前浏览器不支持全屏");
    }
  };

  useEffect(() => {
    const onFsChange = () => {
      setFullscreen(Boolean(document.fullscreenElement));
    };
    document.addEventListener("fullscreenchange", onFsChange);
    return () => document.removeEventListener("fullscreenchange", onFsChange);
  }, []);

  return (
    <div className="soc-dark" ref={rootRef} data-testid="soc-dashboard">
      <div className="soc-header">
        <div>
          <h1 className="soc-brand">ShadowTrace SOC</h1>
          <p className="soc-subtitle">
            事件总览 · 动作执行 / 效果验证 / 写回确认 三率分立
            {loading ? " · 刷新中…" : ""}
          </p>
        </div>
        <Space>
          <Button
            icon={<ReloadOutlined />}
            onClick={() => void refreshAll()}
            data-testid="soc-refresh"
          >
            刷新
          </Button>
          <Button
            type="primary"
            icon={fullscreen ? <FullscreenExitOutlined /> : <FullscreenOutlined />}
            onClick={() => void toggleFullscreen()}
            data-testid="soc-fullscreen"
          >
            {fullscreen ? "退出全屏" : "全屏模式"}
          </Button>
        </Space>
      </div>

      <StatCardGrid stats={stats} />

      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        <Col xs={24} lg={10}>
          <SeverityPieChart bySeverity={stats?.by_severity ?? {}} />
        </Col>
        <Col xs={24} lg={14}>
          <EventTrendChart series={stats?.events_last_24h ?? []} />
        </Col>
      </Row>

      <div style={{ marginTop: 16 }}>
        <HighRiskTicker items={ticker} />
      </div>

      <Typography.Paragraph
        style={{ color: "#8c9bb3", marginTop: 16, marginBottom: 0, fontSize: 12 }}
      >
        30 秒自动刷新 · Socket global 房间增量 · 处置成功率禁止合并为单一指标
      </Typography.Paragraph>
    </div>
  );
}
