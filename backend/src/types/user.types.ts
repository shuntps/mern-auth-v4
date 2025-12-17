import { Document, Types } from 'mongoose';

/**
 * User role type - references Role model
 */
export type UserRole = 'user' | 'admin' | 'super-admin';

/**
 * User Document interface for Mongoose
 */
export interface IUser extends Document {
  _id: Types.ObjectId;
  email: string;
  password?: string;
  firstName: string;
  lastName: string;
  role: Types.ObjectId;
  isEmailVerified: boolean;
  isBanned: boolean;
  avatar?: string;
  googleId?: string;
  twoFactorEnabled: boolean;
  twoFactorSecret?: string;
  passwordChangedAt?: Date;
  lastLogin?: Date;
  lastActivity?: Date;
  ipHistory: string[];
  createdAt: Date;
  updatedAt: Date;

  // Instance methods
  comparePassword(candidatePassword: string): Promise<boolean>;
  changedPasswordAfter(JWTTimestamp: number): boolean;
}

/**
 * User creation input interface (without Mongoose-specific fields)
 */
export interface IUserInput {
  email: string;
  password?: string;
  firstName: string;
  lastName: string;
  role?: Types.ObjectId;
  googleId?: string;
}

/**
 * User response interface (for API responses, excluding sensitive fields)
 */
export interface IUserResponse {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  isEmailVerified: boolean;
  isBanned: boolean;
  avatar?: string;
  twoFactorEnabled: boolean;
  lastLogin?: Date;
  createdAt: Date;
  updatedAt: Date;
}
