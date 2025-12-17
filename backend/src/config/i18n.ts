import { env } from '@config/env';

const translations = {
  en: {
    common: {
      success: 'Success',
      httpsRequired: 'Use HTTPS',
    },
    errors: {
      internal: 'Internal server error',
      validationFailed: 'Validation failed',
      authenticationFailed: 'Authentication failed',
      notAuthenticated: 'Not authenticated',
      accessDenied: 'Access denied',
      notFound: 'Resource not found',
      conflict: 'Resource already exists',
      csrfBlocked: 'Too many invalid CSRF attempts. Please try again later.',
      csrfInvalid: 'Invalid CSRF token',
      userExists: 'User already exists',
      userNotFound: 'User not found',
      accountBanned: 'Account is banned',
      emailNotVerified: 'Email not verified',
      invalidCredentials: 'Invalid email or password',
      refreshTokenMissing: 'Refresh token missing',
      invalidSession: 'Invalid session',
      sessionExpired: 'Session expired',
      sessionMismatch: 'Session token mismatch',
      passwordChanged: 'Password recently changed, please login again',
      googleEmailMissing: 'Google account does not provide an email',
      passwordSame: 'New password must be different from current password',
      invalidResetToken: 'Invalid or expired reset token',
      invalidVerificationToken: 'Invalid or expired verification token',
      passwordRequired: 'Password is required to perform this action',
      twoFactorNotConfigured: 'Two-factor authentication is not configured',
      twoFactorRequired: 'Two-factor code required',
      twoFactorInvalid: 'Invalid two-factor code',
      twoFactorAlreadyEnabled: 'Two-factor authentication is already enabled',
      twoFactorNotEnabled: 'Two-factor authentication is not enabled',
      twoFactorSetupMissing: 'Two-factor setup not found or expired',
      roleMissing: 'Role is missing for this user',
      roleInvalid: 'Invalid or unknown role',
      missingPermissions: 'Missing required permissions',
      tokenGenerationFailed: 'Failed to generate token',
      tokenInvalid: 'Invalid or expired token',
      sessionCreateFailed: 'Failed to create session',
      sessionNotFound: 'Session not found',
      sessionRefreshFailed: 'Failed to refresh session',
      sessionRevokeFailed: 'Failed to revoke session',
      sessionRevokeAllFailed: 'Failed to revoke user sessions',
    },
    auth: {
      loginSuccess: 'Logged in successfully',
      registerSuccess: 'Registered successfully',
      logoutSuccess: 'Logged out successfully',
    },
    validation: {
      email: 'Invalid email address',
      password: {
        min: 'Password must be at least 8 characters',
        uppercase: 'Password must contain at least one uppercase letter',
        lowercase: 'Password must contain at least one lowercase letter',
        number: 'Password must contain at least one number',
        special: 'Password must contain at least one special character',
      },
      required: {
        email: 'Email is required',
        password: 'Password is required',
        firstName: 'First name is required',
        lastName: 'Last name is required',
        token: 'Token is required',
        oldPassword: 'Current password is required',
        newPassword: 'New password is required',
        twoFactorCode: 'Two-factor code is required',
      },
      atLeastOneField: 'Provide at least one field to update',
      max: {
        firstName: 'First name cannot exceed 50 characters',
        lastName: 'Last name cannot exceed 50 characters',
      },
      format: {
        twoFactorCode: 'Two-factor code must be 6 digits',
      },
    },
    csrf: {
      blocked: 'CSRF protection triggered. Please retry later.',
    },
  },
  fr: {
    common: {
      success: 'Succes',
      httpsRequired: 'Utilisez HTTPS',
    },
    errors: {
      internal: 'Erreur interne du serveur',
      validationFailed: 'Validation echouee',
      authenticationFailed: 'Echec de l authentification',
      notAuthenticated: 'Non authentifie',
      accessDenied: 'Acces refuse',
      notFound: 'Ressource introuvable',
      conflict: 'La ressource existe deja',
      csrfBlocked: 'Trop de tentatives CSRF invalides. Reessayez plus tard.',
      csrfInvalid: 'Jeton CSRF invalide',
      userExists: 'Utilisateur existe deja',
      userNotFound: 'Utilisateur introuvable',
      accountBanned: 'Compte bloque',
      emailNotVerified: 'Email non verifie',
      invalidCredentials: 'Email ou mot de passe invalide',
      refreshTokenMissing: 'Jeton d actualisation manquant',
      invalidSession: 'Session invalide',
      sessionExpired: 'Session expiree',
      sessionMismatch: 'Jeton de session non correspondant',
      passwordChanged: 'Mot de passe modifie recemment, reconnectez vous',
      googleEmailMissing: 'Le compte Google ne fournit pas d email',
      passwordSame: 'Le nouveau mot de passe doit etre different',
      invalidResetToken: 'Jeton de reinitialisation invalide ou expire',
      invalidVerificationToken: 'Jeton de verification invalide ou expire',
      passwordRequired: 'Mot de passe requis pour cette action',
      twoFactorNotConfigured: 'La double authentification n est pas configuree',
      twoFactorRequired: 'Code de double authentification requis',
      twoFactorInvalid: 'Code de double authentification invalide',
      twoFactorAlreadyEnabled: 'Double authentification deja activee',
      twoFactorNotEnabled: 'Double authentification non activee',
      twoFactorSetupMissing: 'Configuration double authentification introuvable ou expiree',
      roleMissing: 'Role manquant pour cet utilisateur',
      roleInvalid: 'Role invalide ou inconnu',
      missingPermissions: 'Permissions requises manquantes',
      tokenGenerationFailed: 'Echec de generation du jeton',
      tokenInvalid: 'Jeton invalide ou expire',
      sessionCreateFailed: 'Echec de creation de session',
      sessionNotFound: 'Session introuvable',
      sessionRefreshFailed: 'Echec de mise a jour de session',
      sessionRevokeFailed: 'Echec de revocation de session',
      sessionRevokeAllFailed: 'Echec de revocation des sessions utilisateur',
    },
    auth: {
      loginSuccess: 'Connexion reussie',
      registerSuccess: 'Inscription reussie',
      logoutSuccess: 'Deconnexion reussie',
    },
    validation: {
      email: 'Adresse email invalide',
      password: {
        min: 'Le mot de passe doit contenir au moins 8 caracteres',
        uppercase: 'Le mot de passe doit contenir une majuscule',
        lowercase: 'Le mot de passe doit contenir une minuscule',
        number: 'Le mot de passe doit contenir un chiffre',
        special: 'Le mot de passe doit contenir un caractere special',
      },
      required: {
        email: 'Email requis',
        password: 'Mot de passe requis',
        firstName: 'Prenom requis',
        lastName: 'Nom requis',
        token: 'Jeton requis',
        oldPassword: 'Mot de passe actuel requis',
        newPassword: 'Nouveau mot de passe requis',
        twoFactorCode: 'Code de double authentification requis',
      },
      atLeastOneField: 'Fournissez au moins un champ a mettre a jour',
      max: {
        firstName: 'Le prenom ne peut pas depasser 50 caracteres',
        lastName: 'Le nom ne peut pas depasser 50 caracteres',
      },
      format: {
        twoFactorCode: 'Le code de double authentification doit avoir 6 chiffres',
      },
    },
    csrf: {
      blocked: 'Protection CSRF activee. Reessayez plus tard.',
    },
  },
} as const;

type Translations = typeof translations;
type Locale = keyof Translations;

type LeafPaths<T, Prefix extends string = ''> = {
  [K in keyof T]: T[K] extends Record<string, unknown>
    ? LeafPaths<T[K], `${Prefix}${Extract<K, string>}.`>
    : `${Prefix}${Extract<K, string>}`;
}[keyof T];

export type TranslationKey = LeafPaths<Translations['en']>;

export type TranslationParams = Record<string, string | number | boolean>;

export type TranslateFn = (key: TranslationKey, params?: TranslationParams) => string;

export interface I18nInstance {
  translations: typeof translations;
  supportedLocales: string[];
  defaultLocale: Locale;
  resolveLocale: (requested?: string) => Locale;
  translate: (locale: Locale, key: TranslationKey, params?: TranslationParams) => string;
  getTranslator: (locale?: string) => TranslateFn;
}

const getValueByPath = (locale: Locale, key: string): string | undefined => {
  const segments = key.split('.');
  let current: unknown = translations[locale];
  for (const segment of segments) {
    if (!current || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return typeof current === 'string' ? current : undefined;
};

const formatMessage = (template: string, params?: TranslationParams): string => {
  if (!params) return template;
  return Object.entries(params).reduce((acc, [name, value]) => {
    return acc.replace(new RegExp(`{{${name}}}`, 'g'), String(value));
  }, template);
};

const normalizeLocale = (locale?: string): string | undefined => {
  if (!locale) return undefined;
  return locale.toLowerCase().replace('_', '-');
};

const isKnownLocale = (value?: string): value is Locale =>
  Boolean(value && Object.hasOwn(translations, value));

export const createI18n = (options?: {
  defaultLocale?: string;
  supportedLocales?: string[];
}): I18nInstance => {
  const supportedLocales = (options?.supportedLocales ?? env.supportedLanguages).map((value) =>
    value.toLowerCase()
  );
  const normalizedDefault = normalizeLocale(options?.defaultLocale ?? env.defaultLanguage);
  const defaultLocale = isKnownLocale(normalizedDefault) ? normalizedDefault : 'en';

  const resolveLocale = (requested?: string): Locale => {
    const normalized = normalizeLocale(requested);
    if (isKnownLocale(normalized)) {
      return normalized;
    }
    const base = normalized?.split('-')[0];
    if (isKnownLocale(base)) {
      return base;
    }

    const fallback = supportedLocales.find((value): value is Locale => isKnownLocale(value));
    return fallback ?? defaultLocale;
  };

  const translate = (locale: Locale, key: TranslationKey, params?: TranslationParams): string => {
    const value = getValueByPath(locale, key) ?? getValueByPath('en', key);
    if (!value) return key;
    return formatMessage(value, params);
  };

  const getTranslator = (locale?: string): TranslateFn => {
    const resolved = resolveLocale(locale);
    return (key, params) => translate(resolved, key, params);
  };

  return {
    translations,
    supportedLocales,
    defaultLocale,
    resolveLocale,
    translate,
    getTranslator,
  };
};

const i18n = createI18n();

export default i18n;
