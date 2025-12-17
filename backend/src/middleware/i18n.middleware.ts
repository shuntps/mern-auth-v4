import { type RequestHandler } from 'express';
import i18n from '@config/i18n';
import { env } from '@config/env';

const parseAcceptLanguage = (headerValue?: string): string[] => {
  if (!headerValue) return [];
  return headerValue
    .split(',')
    .map((part) => {
      const [langPart] = part.split(';');
      return (langPart ?? '').trim();
    })
    .filter((value): value is string => Boolean(value));
};

const candidatesFromRequest = (req: Parameters<RequestHandler>[0]): string[] => {
  const queryLocale = typeof req.query.lang === 'string' ? req.query.lang : undefined;
  const cookieLocale = (req.cookies as Record<string, unknown> | undefined)?.lang;
  const headerLocale = req.get('x-locale') ?? req.get('x-lang');
  const acceptLanguages = parseAcceptLanguage(req.get('accept-language'));

  const values = [queryLocale, cookieLocale, headerLocale, ...acceptLanguages];
  return values
    .map((value) => (typeof value === 'string' ? value : undefined))
    .filter((value): value is string => Boolean(value));
};

export const i18nMiddleware: RequestHandler = (req, res, next) => {
  const requested = candidatesFromRequest(req).find(Boolean);
  const locale = i18n.resolveLocale(requested ?? env.defaultLanguage);
  const t = i18n.getTranslator(locale);

  req.locale = locale;
  res.locals.locale = locale;
  res.locals.t = t;

  next();
};
