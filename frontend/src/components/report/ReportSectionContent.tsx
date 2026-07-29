/** Markdown section body with plain-text fallback (ISSUE-074). */

import { Component, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Typography } from "antd";

const { Text } = Typography;

class MarkdownRenderBoundary extends Component<
  { content: string; children: ReactNode },
  { failed: boolean }
> {
  override state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  override render() {
    if (this.state.failed) {
      return <Text style={{ whiteSpace: "pre-wrap" }}>{this.props.content}</Text>;
    }
    return this.props.children;
  }
}

export default function ReportSectionContent({ content }: { content: string }) {
  return (
    <MarkdownRenderBoundary content={content}>
      <div className="report-section-markdown">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
      </div>
    </MarkdownRenderBoundary>
  );
}
