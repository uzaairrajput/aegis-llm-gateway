export type Detector = "injection" | "pii" | "topic" | "canary" | "model";

export interface Finding {
  detector: Detector;
  rule: string;
  severity: "low" | "medium" | "high";
  score?: number;
  messageIndex?: number;
  /** Short excerpt of the matched text. Never populated for PII. */
  excerpt?: string;
}
