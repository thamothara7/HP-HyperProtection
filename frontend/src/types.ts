export type Status = "NORMAL" | "ELEVATED" | "HIGH" | "DECEPTION_ELIGIBLE" | "DECEPTION" | "CONTAINED" | "CLOSED";
export type Intent = "NONE" | "RECON" | "CREDENTIAL_HUNTING" | "LATERAL_MOVEMENT" | "EXFIL_ATTEMPT";

export interface TimelineEvent { timestamp: string; event_type: string; title: string; detail: string; risk_change?: number | null }
export interface Session { id: string; identity_id: string; device_id: string; risk_score: number; intent: Intent; intent_confidence: number; status: Status; started_at: string; is_contained: boolean; approved_override: boolean }
export interface SessionDetail extends Session { anomaly_score: number; sequence_score: number; device_deviation: string; new_hosts: number; remote_access_ratio: number; privilege_attempts: number; reason_codes: string[]; timeline: TimelineEvent[]; baseline_comparison: [string, string, string][] }
export interface Overview { active_sessions: number; elevated_sessions: number; critical_sessions: number; risk_activity: number[]; attention_sessions: Session[]; generated_at: string }
export interface LiveTelemetryEvent { type: string; event_id: string; timestamp: string; identity_id: string; session_id: string; device_id: string; event_type: string; target?: string | null; result: string }
export interface Identity { id: string; department: string | null; role: string | null; sessions: Session[] }
export interface BaselineResponse { identity_id: string; learning_policy: { normal_below: number; reduced_through: number; frozen_above: number }; personal: { trusted_observations: number; profile: Record<string, unknown> } | null; peer: { department: string; role: string; profile: Record<string, unknown> } | null }
export interface Incident { id: string; session_id: string; title: string; severity: string; status: string; summary: string; created_at: string }
export interface DecoyResource { path: string; title: string; content_type: string; synthetic: boolean }
export interface DecoyInteraction { session_id: string; resource: string; action: string; confidence_delta: number; observed_at: string }
export interface Policy { id: string; name: string; scope: string; state: string }
export interface Scenario { id: string; name: string; description: string; expected_outcome: string }
