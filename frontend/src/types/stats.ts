/** Stats API types (ISSUE-085 SOC dashboard). */

export interface RateStat {
  rate: number | null;
  numerator: number;
  denominator: number;
}

export interface HourlyEventCount {
  hour: string;
  count: number;
}

export interface StatsResponse {
  total_events: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  by_event_type: Record<string, number>;
  action_execution_success_rate: RateStat;
  effect_verification_rate: RateStat;
  writeback_confirmation_rate: RateStat;
  avg_investigation_seconds: number | null;
  events_last_24h: HourlyEventCount[];
  open_events: number;
  closed_events: number;
  pending_approvals: number;
  pending_writebacks: number;
  external_unsynced_events: number;
}
