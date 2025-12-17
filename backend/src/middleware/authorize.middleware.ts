import { type NextFunction, type Request, type Response } from 'express';
import { AuthenticationError, AuthorizationError } from '@utils/errors';
import Role from '@models/role.model';
import { type UserRole } from '@custom-types/user.types';

interface RoleInfo {
  name: UserRole;
  permissions: string[];
}

const roleHierarchy: UserRole[] = ['user', 'admin', 'super-admin'];
const roleCache = new Map<string, RoleInfo>();

const isUserRole = (value: string): value is UserRole => {
  return roleHierarchy.includes(value as UserRole);
};

const getRoleInfo = async (roleId?: string): Promise<RoleInfo> => {
  if (!roleId) {
    throw new AuthorizationError('Role is missing for this user');
  }

  const cached = roleCache.get(roleId);
  if (cached) {
    return cached;
  }

  const roleDoc = await Role.findById(roleId).select('name permissions').lean();
  if (!roleDoc || !isUserRole(roleDoc.name)) {
    throw new AuthorizationError('Invalid or unknown role');
  }

  const roleInfo: RoleInfo = {
    name: roleDoc.name,
    permissions: roleDoc.permissions,
  };

  roleCache.set(roleId, roleInfo);
  return roleInfo;
};

const isRoleAtLeast = (current: UserRole, required: UserRole): boolean => {
  return roleHierarchy.indexOf(current) >= roleHierarchy.indexOf(required);
};

const hasPermission = (permissions: string[], required: string): boolean => {
  return permissions.includes('*') || permissions.includes(required);
};

const hasRequiredPermissions = (
  permissions: string[],
  required: string[],
  mode: 'all' | 'any'
): boolean => {
  if (required.length === 0) {
    return true;
  }

  return mode === 'any'
    ? required.some((permission) => hasPermission(permissions, permission))
    : required.every((permission) => hasPermission(permissions, permission));
};

const attachRoleContext = (
  res: Response,
  roleInfo: RoleInfo,
  authContext: { userId: string; role?: string }
): void => {
  res.locals.auth = {
    ...authContext,
    role: authContext.role ?? roleInfo.name,
    roleName: roleInfo.name,
    permissions: roleInfo.permissions,
  };
};

export const authorize = (...allowedRoles: UserRole[]) => {
  return async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authContext = res.locals.auth;
      if (!authContext?.userId) {
        throw new AuthenticationError('Not authenticated');
      }

      const roleInfo = await getRoleInfo(authContext.role);
      attachRoleContext(res, roleInfo, authContext);

      if (allowedRoles.length === 0) {
        next();
        return;
      }

      const isAllowed = allowedRoles.some((requiredRole) =>
        isRoleAtLeast(roleInfo.name, requiredRole)
      );

      if (!isAllowed) {
        throw new AuthorizationError('Access denied');
      }

      next();
    } catch (error) {
      next(error as Error);
    }
  };
};

export const authorizePermissions = (
  requiredPermissions: string[],
  options?: { mode?: 'all' | 'any' }
) => {
  const mode = options?.mode ?? 'all';

  return async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authContext = res.locals.auth;
      if (!authContext?.userId) {
        throw new AuthenticationError('Not authenticated');
      }

      const roleInfo = await getRoleInfo(authContext.role);
      attachRoleContext(res, roleInfo, authContext);

      const authorized = hasRequiredPermissions(roleInfo.permissions, requiredPermissions, mode);
      if (!authorized) {
        throw new AuthorizationError('Missing required permissions');
      }

      next();
    } catch (error) {
      next(error as Error);
    }
  };
};

export const hasRoleAtLeast = (current: UserRole, required: UserRole): boolean => {
  return isRoleAtLeast(current, required);
};

export const getRoleHierarchy = (): readonly UserRole[] => roleHierarchy;
