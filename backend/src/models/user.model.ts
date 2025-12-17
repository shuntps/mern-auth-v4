import mongoose, { Schema } from 'mongoose';
import bcrypt from 'bcrypt';
import { IUser } from '@custom-types/user.types';
import { env } from '@config/env';
import Role from './role.model';

/**
 * User Schema
 * Manages user data with authentication and profile information
 */
const userSchema = new Schema<IUser>(
  {
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      validate: {
        validator: (value: string): boolean => {
          return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
        },
        message: 'Please provide a valid email address',
      },
    },
    password: {
      type: String,
      select: false, // Don't include password in queries by default
      minlength: [8, 'Password must be at least 8 characters'],
    },
    firstName: {
      type: String,
      required: [true, 'First name is required'],
      trim: true,
      maxlength: [50, 'First name cannot exceed 50 characters'],
    },
    lastName: {
      type: String,
      required: [true, 'Last name is required'],
      trim: true,
      maxlength: [50, 'Last name cannot exceed 50 characters'],
    },
    role: {
      type: Schema.Types.ObjectId,
      ref: 'Role',
      required: [true, 'User role is required'],
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    isBanned: {
      type: Boolean,
      default: false,
    },
    avatar: {
      type: String,
      default: null,
    },
    googleId: {
      type: String,
      unique: true,
      sparse: true, // Allow null values to be non-unique
    },
    twoFactorEnabled: {
      type: Boolean,
      default: false,
    },
    twoFactorSecret: {
      type: String,
      select: false, // Don't include in queries by default
    },
    passwordChangedAt: {
      type: Date,
    },
    lastLogin: {
      type: Date,
    },
    lastActivity: {
      type: Date,
    },
    ipHistory: {
      type: [String],
      default: [],
      validate: {
        validator: (value: string[]): boolean => {
          // Keep only last 10 IP addresses
          return value.length <= 10;
        },
        message: 'IP history cannot exceed 10 entries',
      },
    },
  },
  {
    timestamps: true,
  }
);

// Additional indexes for performance (unique fields already indexed by schema definitions)
userSchema.index({ role: 1 });
userSchema.index({ isEmailVerified: 1 });
userSchema.index({ isBanned: 1 });

/**
 * Pre-validate middleware: Assign default role if not present
 */
userSchema.pre('validate', async function (this: IUser) {
  if (this.isNew && !this.get('role')) {
    const userRole = await Role.findOne({ name: 'user' });
    if (userRole) {
      this.set('role', userRole._id);
    }
  }
});

/**
 * Pre-save middleware: Hash password before saving
 * Only runs if password is modified or new
 */
userSchema.pre('save', async function (this: IUser) {
  // Only hash password if it has been modified (or is new)
  if (!this.isModified('password') || !this.password) {
    return;
  }

  const salt: string = await bcrypt.genSalt(env.bcryptRounds);
  const hashedPassword: string = await bcrypt.hash(this.password, salt);
  this.password = hashedPassword;

  if (!this.isNew) {
    this.passwordChangedAt = new Date(Date.now() - 1000); // Ensure JWT issued after password change
  }
});

/**
 * Instance method: Compare candidate password with hashed password
 * @param candidatePassword - Plain text password to compare
 * @returns Promise<boolean> - True if passwords match
 */
userSchema.methods.comparePassword = async function (
  this: IUser,
  candidatePassword: string
): Promise<boolean> {
  if (!this.password) {
    return false;
  }
  const isMatch: boolean = await bcrypt.compare(candidatePassword, this.password);
  return isMatch;
};

/**
 * Instance method: Check if password was changed after JWT was issued
 * Used to invalidate old tokens when password is changed
 * @param JWTTimestamp - JWT issued at timestamp (in seconds)
 * @returns boolean - True if password was changed after JWT was issued
 */
userSchema.methods.changedPasswordAfter = function (this: IUser, JWTTimestamp: number): boolean {
  if (this.passwordChangedAt) {
    const changedDate: Date = this.passwordChangedAt;
    const changedTimestamp = Math.floor(changedDate.getTime() / 1000);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

const User = mongoose.model<IUser>('User', userSchema);

export default User;
