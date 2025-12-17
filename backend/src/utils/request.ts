import crypto from 'crypto';
import { type Request } from 'express';
import { type SessionMetadata } from '@services/session.service';

const stripIpv6Prefix = (ip: string): string => {
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
};

const parseForwardedFor = (headerValue: string | string[] | undefined): string | undefined => {
  if (!headerValue) return undefined;
  const raw = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (!raw) return undefined;
  const first = raw.split(',')[0]?.trim();
  return first ? stripIpv6Prefix(first) : undefined;
};

export const getClientIp = (req: Request): string | undefined => {
  const forwarded = parseForwardedFor(req.headers['x-forwarded-for']);
  if (forwarded) return forwarded;

  if (req.ip) return stripIpv6Prefix(req.ip);
  const remote = req.socket.remoteAddress;
  return remote ? stripIpv6Prefix(remote) : undefined;
};

export const buildRequestFingerprint = (req: Request): string => {
  const ip = getClientIp(req) ?? 'unknown';
  const userAgent = req.get('user-agent') ?? 'unknown';
  const acceptLanguage = req.get('accept-language') ?? '';
  const acceptEncoding = req.get('accept-encoding') ?? '';
  const secChUa = req.get('sec-ch-ua') ?? '';
  const platform = req.get('sec-ch-ua-platform') ?? '';
  const mobile = req.get('sec-ch-ua-mobile') ?? '';

  const raw = [ip, userAgent, acceptLanguage, acceptEncoding, secChUa, platform, mobile].join('|');
  return crypto.createHash('sha256').update(raw).digest('hex');
};

export const buildSessionMetadata = (req: Request): SessionMetadata => ({
  ip: getClientIp(req),
  userAgent: req.get('user-agent') ?? undefined,
  browser: req.get('sec-ch-ua') ?? undefined,
  os: req.get('sec-ch-ua-platform') ?? undefined,
  device: req.get('sec-ch-ua-mobile') ?? undefined,
});
