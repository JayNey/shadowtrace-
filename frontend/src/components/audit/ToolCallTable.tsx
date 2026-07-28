import { Button, Space, Table, Tag, Typography } from "antd";
import { EyeOutlined } from "@ant-design/icons";
import type { ColumnsType } from "antd/es/table";
import { Link } from "react-router-dom";
import type { ToolCallItem } from "../../types/trace";

function callStatus(value: string) {
  if (value === "success") {
    return <Tag color="blue">Action success</Tag>;
  }
  if (value === "failed" || value === "timeout") {
    return <Tag color="red">{value}</Tag>;
  }
  if (value === "running") {
    return <Tag color="processing">running</Tag>;
  }
  return <Tag>{value}</Tag>;
}

function writebackStatus(value: string | null) {
  if (!value) return <Typography.Text type="secondary">—</Typography.Text>;
  if (value.toLowerCase() === "confirmed") {
    return <Tag color="green">Writeback confirmed</Tag>;
  }
  return <Tag color="gold">{value}</Tag>;
}

export default function ToolCallTable({
  items,
  loading = false,
  total,
  page,
  pageSize,
  onPageChange,
  onSelect,
  showEvent = true,
}: {
  items: ToolCallItem[];
  loading?: boolean;
  total: number;
  page: number;
  pageSize: number;
  onPageChange?: (page: number, pageSize: number) => void;
  onSelect: (item: ToolCallItem) => void;
  showEvent?: boolean;
}) {
  const columns: ColumnsType<ToolCallItem> = [
    {
      title: "工具",
      dataIndex: "tool_name",
      width: 190,
      render: (value: string, row) => (
        <Space direction="vertical" size={0}>
          <Typography.Text strong>{value}</Typography.Text>
          <Typography.Text type="secondary">{row.tool_category}</Typography.Text>
        </Space>
      ),
    },
    ...(showEvent
      ? [
          {
            title: "事件",
            dataIndex: "event_id",
            width: 170,
            render: (value: string) => <Link to={`/events/${value}#audit`}>{value}</Link>,
          } satisfies ColumnsType<ToolCallItem>[number],
        ]
      : []),
    {
      title: "调用状态",
      dataIndex: "status",
      width: 145,
      render: callStatus,
    },
    {
      title: "外部写回",
      dataIndex: "writeback_status",
      width: 180,
      render: writebackStatus,
    },
    {
      title: "provider",
      dataIndex: "provider",
      width: 145,
      render: (value: string | null) => value || "—",
    },
    {
      title: "execution_owner",
      dataIndex: "execution_owner",
      width: 170,
      render: (value: string | null) => value || "—",
    },
    {
      title: "disposition_id",
      dataIndex: "disposition_id",
      width: 180,
      render: (value: string | null) => value || "—",
    },
    {
      title: "耗时 / 重试",
      width: 130,
      render: (_, row) => (
        <span>
          {row.duration_ms === null ? "—" : `${row.duration_ms} ms`} / {row.retry_count}
        </span>
      ),
    },
    {
      title: "详情",
      key: "detail",
      fixed: "right",
      width: 90,
      render: (_, row) => (
        <Button
          type="link"
          icon={<EyeOutlined />}
          onClick={() => onSelect(row)}
          aria-label={`查看 ${row.tool_name} 调用详情`}
        >
          查看
        </Button>
      ),
    },
  ];

  return (
    <Table
      rowKey="call_id"
      loading={loading}
      dataSource={items}
      columns={columns}
      locale={{ emptyText: "暂无工具调用记录" }}
      scroll={{ x: 1280 }}
      pagination={{
        current: page,
        pageSize,
        total,
        showSizeChanger: true,
        showTotal: (count) => `共 ${count} 条`,
        onChange: onPageChange,
      }}
    />
  );
}
