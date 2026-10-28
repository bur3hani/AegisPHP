export type ChannelType = 'smtp_mail' | 'direct_message' | 'contact_form' | 'api_webhook';

export type VerdictType = 'ALLOW' | 'CHALLENGE' | 'BLOCK';

export interface DefenseConfig {
  // General & Thresholds
  blockThreshold: number; // default 70
  challengeThreshold: number; // default 40
  enforceBannerAgreement: boolean;
  protectSmtpHeaders: boolean;
  protectDirectMessages: boolean;

  // Vector 1: IP Reputation
  blockTorAndProxies: boolean;
  flagDatacenterAsns: boolean;
  enableDnsblLookup: boolean;
  ipRateLimitPerMinute: number;

  // Vector 2: Email Format & SMTP Hygiene
  blockDisposableEmails: boolean;
  blockPlusAddressingAbuse: boolean;
  maxEmailLocalEntropy: number; // default 4.1 bits
  verifyMxRecords: boolean;

  // Vector 3: Behavioral & Payload Heuristics
  maxInputEntropy: number; // default 4.45 bits
  detectKeyboardMash: boolean;
  minHumanTypingMs: number; // default 1200ms
  blockSqlAndXss: boolean;
  blockSmtpHeaderInjection: boolean;
  maxUrlsAllowed: number; // default 2

  // Vector 4: HTTP Request Headers
  requireSecFetchHeaders: boolean;
  requireAcceptLanguage: boolean;
  blockAutomatedUserAgents: boolean;
  inspectForwardedForSpoofing: boolean;

  // UK GDPR / Data Protection Act 2018 / PECR Compliance
  organizationName: string;
  icoRegistrationNumber: string;
  dpoContactEmail: string;
  ipPseudonymisationMode: 'hmac_daily_salt' | 'subnet_zero' | 'dual_hmac_subnet';
  logRetentionDays: number; // e.g., 30 days per UK data minimisation
  bannerPosition: 'bottom_bar' | 'top_bar' | 'inline_form_gate';
  bannerRequireExplicitAck: boolean;

  // Critical Risk Incident Alerting
  enableCriticalEmailAlerts: boolean;
  criticalRiskThreshold: number; // default 85
  alertEmailAddress: string;
}

export interface BehavioralTelemetry {
  typingDurationMs: number;
  keystrokeCount: number;
  pasteEventsCount: number;
  honeypotFilled: boolean;
  bannerAgreed: boolean;
  jsTokenPresent: boolean;
}

export interface ScreeningRequest {
  id?: string;
  timestamp?: string;
  channel: ChannelType;
  clientIp: string;
  senderEmail: string;
  recipientOrTarget: string;
  subjectOrTopic: string;
  messageBody: string;
  headers: Record<string, string>;
  telemetry: BehavioralTelemetry;
}

export interface VectorBreakdown {
  score: number; // 0 - 100 contribution
  status: 'CLEAN' | 'ELEVATED' | 'CRITICAL';
  summary: string;
  flags: string[];
  metrics: Record<string, string | number>;
}

export interface ScreeningResult {
  id: string;
  timestamp: string;
  channel: ChannelType;
  verdict: VerdictType;
  totalRiskScore: number;
  criticalAlertTriggered: boolean;
  alertDispatchedTo: string | null;
  smtpSafeToDispatch: boolean;
  dmSafeToDeliver: boolean;
  rawClientIp: string;
  pseudonymisedIp: string;
  senderEmail: string;
  subjectOrTopic: string;
  messagePreview: string;
  vectors: {
    ipReputation: VectorBreakdown;
    emailHygiene: VectorBreakdown;
    behaviorAndPayload: VectorBreakdown;
    requestHeaders: VectorBreakdown;
  };
  ukCompliance: {
    lawfulBasis: string;
    pecrExemption: string;
    bannerAcknowledged: boolean;
    pseudonymisationMethod: string;
    retentionExpiresAt: string;
  };
}

export type UserRole = 'admin' | 'responder' | 'auditor' | 'readonly';

export interface AegisUser {
  id: number;
  uuid: string;
  email: string;
  name: string;
  role: UserRole;
  status: 'active' | 'disabled';
  failedAttempts: number;
  mustChangePassword: boolean;
  lastLoginAt: string | null;
  createdAt: string;
}

export interface PasswordResetRecord {
  id: number;
  userId: number;
  email: string;
  token: string;
  tokenHash: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

export interface AuthAuditRecord {
  id: number;
  timestamp: string;
  eventType: 'login_success' | 'login_failed' | 'account_locked' | 'password_reset_requested' | 'password_reset_success' | 'user_created' | 'user_status_changed';
  email: string;
  success: boolean;
  details: string;
}
