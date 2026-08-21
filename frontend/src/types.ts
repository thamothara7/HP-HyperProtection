export type Status = "NORMAL" | "ELEVATED" | "HIGH" | "DECEPTION_ELIGIBLE" | "DECEPTION" | "CONTAINED" | "CLOSED";
export type Intent = "NONE" | "RECON" | "CREDENTIAL_HUNTING" | "LATERAL_MOVEMENT" | "EXFIL_ATTEMPT";

export interface TimelineEvent { timestamp: string; event_type: string; title: string; detail: string; risk_change?: number | null }
export interface Session { id: string; identity_id: string; device_id: string; risk_score: number; intent: Intent; intent_confidence: number; status: Status; started_at: string; is_contained: boolean; approved_override: boolean }
export interface SessionDetail extends Session { anomaly_score: number; sequence_score: number; device_deviation: string; new_hosts: number; remote_access_ratio: number; privilege_attempts: number; reason_codes: string[]; timeline: TimelineEvent[]; baseline_comparison: [string, string, string][] }
export interface Overview { active_sessions: number; elevated_sessions: number; critical_sessions: number; risk_activity: number[]; attention_sessions: Session[]; generated_at: string }
