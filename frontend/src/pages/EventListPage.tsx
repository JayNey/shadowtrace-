/** EventListPage — event board with filters, pagination, realtime & trigger (ISSUE-068).

  Features:
  1. List loading with status / severity / event_type filters + pagination.
     Filter & page params are synced to URL query (refresh-preserving).
  2. Socket subscription (global): event_created inserts a new row at top,
     state_change updates the row's local status in place,
     writeback_updated updates the writeback badge in place.
  3. "触发研判" button calls triggerInvestigation; on 409 shows a hint toast.
  4. Falls back to polling when socket is unavailable (ISSUE-067 mechanism).
*/

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Card,
  Col,
  Form,
  Row,
  Select,
  Space,
  Typography,
  Button as AntButton,
  App,
} from "antd";
import { ReloadOutlined, FilterOutlined } from "@ant-design/icons";
import type { EventListItem, EventListParams, EventStatus, EventType, Severity } from "../types/event";
import { listEvents, triggerInvestigation } from "../services/eventApi";
import { socketClient } from "../services/socketClient";
import { ApiError } from "../services/apiClient";
import EventTable from "../components/event/EventTable";
import {
  SEVERITY_FILTER_OPTIONS,
  STATUS_FILTER_OPTIONS,
  EVENT_TYPE_OPTIONS,
} from "../components/event/constants";
import { mapSocketWritebackStatus } from "../types/socket";

const DEFAULT_PAGE_SIZE = 20;

/** Parse a numeric query param. */
function parseNum(v: string | null, fallback: number): number {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/** Read filter+page params from URL search params. */
interface ResolvedParams {
  page: number;
  page_size: number;
  status?: EventStatus;
  severity?: Severity;
  event_type?: EventType;
}

function paramsFromURL(sp: URLSearchParams): ResolvedParams {
  const status = sp.get("status");
  const severity = sp.get("severity");
  const event_type = sp.get("event_type");
  return {
    page: parseNum(sp.get("page"), 1),
    page_size: parseNum(sp.get("page_size"), DEFAULT_PAGE_SIZE),
    status: status ? (status as EventStatus) : undefined,
    severity: severity ? (severity as Severity) : undefined,
    event_type: event_type ? (event_type as EventType) : undefined,
  };
}

export default function EventListPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const { message } = App.useApp();

  const filters = useMemo(() => paramsFromURL(searchParams), [searchParams]);

  const [items, setItems] = useState<EventListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [triggeringIds, setTriggeringIds] = useState<Set<string>>(new Set());

  // Keep latest items in a ref so the socket handler (registered once) can
  // mutate without stale-closure issues.
  const itemsRef = useRef<EventListItem[]>(items);
  itemsRef.current = items;
  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  const pollIntervalRef = useRef<number | undefined>(undefined);

  // ---- Data loading ----------------------------------------------------
  const loadEvents = useCallback(
    async (params: EventListParams) => {
      setLoading(true);
      try {
        const res = await listEvents(params);
        setItems(res.data.items);
        setTotal(res.data.total);
      } catch {
        // apiClient interceptor already toasts the error.
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    loadEvents(filters);
  }, [filters, loadEvents]);

  // ---- Socket subscription (global) ------------------------------------
  useEffect(() => {
    socketClient.connect();
    const unsub = socketClient.onEvent((evt) => {
      const current = itemsRef.current;
      if (evt.type === "event_created") {
        // Insert a new row at top — only if not already present.
        const newId = evt.payload.event_id;
        if (current.some((it) => it.event_id === newId)) return;
        const newItem: EventListItem = {
          event_id: newId,
          event_type: (evt.payload.event_type as EventType) ?? "other",
          title: "（新建事件）",
          status: "new",
          severity: (evt.payload.severity as Severity) ?? "low",
          risk_score: 0,
          final_verdict: "none",
          writeback_required: false,
          writeback_readiness: "not_required",
          writeback_overall_status: null,
          pending_writeback_count: 0,
          created_at: evt.payload.created_at ?? new Date().toISOString(),
          updated_at: null,
          occurred_at: null,
        };
        setItems((prev) => [newItem, ...prev]);
        setTotal((t) => t + 1);
        message.info(`新事件已到达：${newId}`, 3);
      } else if (evt.type === "state_change") {
        const toStatus = evt.payload.to_status as EventStatus;
        const externalUnsynced =
          typeof evt.payload.external_unsynced === "boolean"
            ? evt.payload.external_unsynced
            : undefined;
        setItems((prev) =>
          prev.map((it) =>
            it.event_id === evt.event_id
              ? {
                  ...it,
                  status: toStatus,
                  updated_at: new Date().toISOString(),
                  ...(externalUnsynced !== undefined
                    ? { external_unsynced: externalUnsynced }
                    : {}),
                }
              : it,
          ),
        );
      } else if (evt.type === "writeback_updated") {
        const wbStatus = mapSocketWritebackStatus(String(evt.payload.status));
        setItems((prev) =>
          prev.map((it) =>
            it.event_id === evt.event_id
              ? { ...it, writeback_overall_status: wbStatus }
              : it,
          ),
        );
      }
    });

    // Poll fallback: if socket isn't connected after 5s, start polling.
    const pollCheck = window.setTimeout(() => {
      if (!socketClient.isConnected) {
        pollIntervalRef.current = window.setInterval(() => {
          loadEvents(filtersRef.current);
        }, 10_000);
      }
    }, 5_000);

    return () => {
      unsub();
      window.clearTimeout(pollCheck);
      if (pollIntervalRef.current !== undefined) {
        window.clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = undefined;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---- Filter & pagination handlers -----------------------------------
  const updateParams = useCallback(
    (patch: Partial<EventListParams>) => {
      const next = new URLSearchParams(searchParams);
      // Reset page on filter change unless page explicitly provided.
      if (!("page" in patch)) next.set("page", "1");
      for (const [k, v] of Object.entries(patch)) {
        if (v === undefined || v === null || v === "") {
          next.delete(k);
        } else {
          next.set(k, String(v));
        }
      }
      setSearchParams(next, { replace: false });
    },
    [searchParams, setSearchParams],
  );

  const handlePageChange = useCallback(
    (page: number, pageSize: number) => {
      updateParams({ page, page_size: pageSize });
    },
    [updateParams],
  );

  const handleResetFilters = useCallback(() => {
    const next = new URLSearchParams();
    next.set("page", "1");
    next.set("page_size", String(DEFAULT_PAGE_SIZE));
    setSearchParams(next, { replace: false });
  }, [setSearchParams]);

  // ---- Trigger investigation -----------------------------------------
  const handleTrigger = useCallback(
    async (eventId: string) => {
      setTriggeringIds((prev) => new Set(prev).add(eventId));
      try {
        const res = await triggerInvestigation(eventId);
        const newStatus = (res.data?.status as EventStatus) ?? "triaging";
        setItems((prev) =>
          prev.map((it) =>
            it.event_id === eventId ? { ...it, status: newStatus } : it,
          ),
        );
        message.success(`事件 ${eventId} 已触发研判，进入 ${newStatus}`);
      } catch (err: unknown) {
        if (
          err instanceof ApiError &&
          (err.error_code === "investigation_in_progress" ||
            err.error_code === "conflict")
        ) {
          // 409 — backend uses investigation_in_progress (events.py);
          // keep conflict as a defensive alias.
          message.warning(
            `事件 ${eventId} 已在研判流程中，请勿重复触发。`,
          );
        } else {
          // other errors handled by interceptor; show inline status rollback
        }
      } finally {
        setTriggeringIds((prev) => {
          const next = new Set(prev);
          next.delete(eventId);
          return next;
        });
      }
    },
    [message],
  );

  const handleRowClick = useCallback(
    (eventId: string) => {
      navigate(`/events/${eventId}`);
    },
    [navigate],
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Typography.Title level={3} style={{ margin: 0 }}>
          事件看板
        </Typography.Title>
        <Space>
          <AntButton
            icon={<ReloadOutlined />}
            onClick={() => loadEvents(filters)}
            loading={loading}
          >
            刷新
          </AntButton>
        </Space>
      </div>

      <Card size="small" variant="outlined">
        <Form layout="inline" size="small">
          <Row gutter={[12, 12]} style={{ width: "100%" }}>
            <Col>
              <Form.Item label="状态" style={{ marginBottom: 0 }}>
                <Select
                  allowClear
                  placeholder="全部状态"
                  style={{ minWidth: 140 }}
                  value={filters.status ?? undefined}
                  onChange={(v) => updateParams({ status: v ?? undefined })}
                  options={STATUS_FILTER_OPTIONS}
                  data-testid="filter-status"
                />
              </Form.Item>
            </Col>
            <Col>
              <Form.Item label="严重度" style={{ marginBottom: 0 }}>
                <Select
                  allowClear
                  placeholder="全部严重度"
                  style={{ minWidth: 120 }}
                  value={filters.severity ?? undefined}
                  onChange={(v) => updateParams({ severity: v ?? undefined })}
                  options={SEVERITY_FILTER_OPTIONS}
                  data-testid="filter-severity"
                />
              </Form.Item>
            </Col>
            <Col>
              <Form.Item label="事件类型" style={{ marginBottom: 0 }}>
                <Select
                  allowClear
                  placeholder="全部类型"
                  style={{ minWidth: 140 }}
                  value={filters.event_type ?? undefined}
                  onChange={(v) => updateParams({ event_type: v ?? undefined })}
                  options={EVENT_TYPE_OPTIONS}
                  data-testid="filter-event-type"
                />
              </Form.Item>
            </Col>
            <Col>
              <Form.Item style={{ marginBottom: 0 }}>
                <AntButton
                  icon={<FilterOutlined />}
                  onClick={handleResetFilters}
                  data-testid="filter-reset"
                >
                  重置
                </AntButton>
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Card>

      <Card variant="outlined" styles={{ body: { padding: 0 } }}>
        <EventTable
          items={items}
          loading={loading}
          total={total}
          page={filters.page}
          pageSize={filters.page_size}
          onPageChange={handlePageChange}
          onTriggerInvestigation={handleTrigger}
          triggeringIds={triggeringIds}
          onRowClick={handleRowClick}
        />
      </Card>
    </div>
  );
}
