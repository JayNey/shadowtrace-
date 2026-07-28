import {
  Alert,
  Button,
  Card,
  Col,
  Input,
  Row,
  Select,
  Space,
  Statistic,
  Typography,
} from "antd";
import { ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { useCallback, useEffect, useState } from "react";
import ToolCallDetailDrawer from "../components/audit/ToolCallDetailDrawer";
import ToolCallTable from "../components/audit/ToolCallTable";
import { TOOL_STATUS_OPTIONS } from "../components/audit/constants";
import { listToolCalls } from "../services/auditApi";
import type { ToolCallItem } from "../types/trace";

const DEFAULT_PAGE_SIZE = 20;

export default function ToolAuditPage() {
  const [items, setItems] = useState<ToolCallItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [toolNameInput, setToolNameInput] = useState("");
  const [toolName, setToolName] = useState("");
  const [status, setStatus] = useState<string>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [selectedCall, setSelectedCall] = useState<ToolCallItem | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await listToolCalls({
        page,
        page_size: pageSize,
        tool_name: toolName || undefined,
        status,
      });
      setItems(response.data.items);
      setTotal(response.data.total);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, status, toolName]);

  useEffect(() => {
    void load();
  }, [load]);

  const applyFilters = () => {
    setPage(1);
    setToolName(toolNameInput.trim());
  };

  const resetFilters = () => {
    setToolNameInput("");
    setToolName("");
    setStatus(undefined);
    setPage(1);
  };

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <div>
        <Typography.Title level={3} style={{ marginBottom: 4 }}>
          工具调用审计
        </Typography.Title>
        <Typography.Paragraph type="secondary">
          统一查看工具执行、动作归属、Disposition 和外部写回状态；详情仅展示脱敏限长后的安全审计投影。
        </Typography.Paragraph>
      </div>

      <Row gutter={[12, 12]}>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic title="当前查询总数" value={total} />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="本页成功调用"
              value={items.filter((item) => item.status === "success").length}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="本页失败调用"
              value={
                items.filter((item) =>
                  ["failed", "timeout"].includes(item.status),
                ).length
              }
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="写回已确认"
              value={
                items.filter(
                  (item) => item.writeback_status?.toLowerCase() === "confirmed",
                ).length
              }
            />
          </Card>
        </Col>
      </Row>

      <Card size="small">
        <Space wrap>
          <Input
            allowClear
            aria-label="工具名筛选"
            placeholder="按工具名筛选"
            prefix={<SearchOutlined />}
            value={toolNameInput}
            onChange={(event) => setToolNameInput(event.target.value)}
            onPressEnter={applyFilters}
            style={{ width: 260 }}
          />
          <Select
            allowClear
            aria-label="调用状态筛选"
            placeholder="按状态筛选"
            value={status}
            options={TOOL_STATUS_OPTIONS}
            onChange={(value) => {
              setStatus(value);
              setPage(1);
            }}
            style={{ width: 180 }}
          />
          <Button type="primary" onClick={applyFilters}>
            查询
          </Button>
          <Button onClick={resetFilters}>重置</Button>
          <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void load()}>
            刷新
          </Button>
        </Space>
      </Card>

      {error && (
        <Alert
          type="error"
          showIcon
          message="工具审计加载失败"
          description="请检查服务连接后重试。"
          action={<Button onClick={() => void load()}>重试</Button>}
        />
      )}

      <Card>
        <ToolCallTable
          items={items}
          loading={loading}
          total={total}
          page={page}
          pageSize={pageSize}
          onPageChange={(nextPage, nextPageSize) => {
            setPage(nextPageSize === pageSize ? nextPage : 1);
            setPageSize(nextPageSize);
          }}
          onSelect={setSelectedCall}
        />
      </Card>
      <ToolCallDetailDrawer
        toolCall={selectedCall}
        open={selectedCall !== null}
        onClose={() => setSelectedCall(null)}
      />
    </Space>
  );
}
