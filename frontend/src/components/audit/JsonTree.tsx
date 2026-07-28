import { Tag, Typography } from "antd";
import type { ReactNode } from "react";

const SECRET_KEY =
  /(^|_)(password|passwd|secret|token|api_?key|authorization|cookie|private_?key)($|_)/i;
const HIDDEN_REASONING_KEY =
  /(^|_)(chain_?of_?thought|hidden_?reasoning|internal_?reasoning|system_?prompt|raw_?prompt)($|_)/i;
const RAW_PAYLOAD_KEY = /(^|_)(raw|raw_?payload|raw_?result)($|_)/i;

function safeValue(value: unknown, key?: string): unknown {
  if (key && (SECRET_KEY.test(key) || HIDDEN_REASONING_KEY.test(key))) {
    return "[REDACTED]";
  }
  if (key && RAW_PAYLOAD_KEY.test(key)) {
    if (
      value &&
      typeof value === "object" &&
      ("sha256" in value || "_redacted" in value)
    ) {
      return value;
    }
    return { _redacted: true, reason: "raw_payload_not_displayed" };
  }
  return value;
}

function TreeNode({
  value,
  name,
  depth,
}: {
  value: unknown;
  name?: string;
  depth: number;
}): ReactNode {
  const projected = safeValue(value, name);
  const prefix = name ? (
    <Typography.Text code>{name}</Typography.Text>
  ) : null;

  if (projected === null || typeof projected !== "object") {
    return (
      <div style={{ paddingLeft: depth * 14 }}>
        {prefix}
        {prefix ? ": " : ""}
        <Typography.Text>{String(projected)}</Typography.Text>
      </div>
    );
  }

  const entries = Array.isArray(projected)
    ? projected.map((item, index) => [String(index), item] as const)
    : Object.entries(projected);
  const isTruncated =
    !Array.isArray(projected) &&
    ("_truncated" in projected || Reflect.get(projected, "_redacted") === true);

  return (
    <details open={depth < 1} style={{ paddingLeft: depth * 14 }}>
      <summary>
        {prefix ?? (Array.isArray(projected) ? "Array" : "Object")}{" "}
        <Typography.Text type="secondary">({entries.length})</Typography.Text>
        {isTruncated && <Tag color="orange">truncated / redacted</Tag>}
      </summary>
      {entries.map(([childName, childValue]) => (
        <TreeNode
          key={`${depth}-${childName}`}
          name={childName}
          value={childValue}
          depth={depth + 1}
        />
      ))}
    </details>
  );
}

export default function JsonTree({ value }: { value: unknown }) {
  return (
    <div
      style={{
        maxHeight: 300,
        overflow: "auto",
        padding: 12,
        borderRadius: 6,
        background: "#fafafa",
      }}
    >
      <TreeNode value={value} depth={0} />
    </div>
  );
}
