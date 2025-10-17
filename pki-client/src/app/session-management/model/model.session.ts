export interface ActiveSession {
  jti: string;
  ipAddress: string;
  userAgent: string;
  lastActivity: string;
  expiresAt: string;
}

export interface ParsedSession extends ActiveSession {
  device: { icon: string; name: string; };
  browser: { icon: string; name: string; };
  isCurrentSession: boolean;
}