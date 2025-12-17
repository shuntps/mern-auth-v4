import mongoose, { Schema, Document } from 'mongoose';

/**
 * Role Document interface extending Mongoose Document
 */
export interface IRole extends Document {
  name: string;
  permissions: string[];
  description?: string;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Role Schema
 * Manages user roles and permissions dynamically
 */
const roleSchema = new Schema<IRole>(
  {
    name: {
      type: String,
      required: [true, 'Role name is required'],
      unique: true,
      trim: true,
      lowercase: true,
      enum: ['user', 'admin', 'super-admin'],
    },
    permissions: {
      type: [String],
      default: [],
    },
    description: {
      type: String,
      trim: true,
    },
  },
  {
    timestamps: true,
  }
);

/**
 * Seed default roles if they don't exist
 */
export const seedDefaultRoles = async (): Promise<void> => {
  const Role = mongoose.model<IRole>('Role', roleSchema);

  const defaultRoles = [
    {
      name: 'user',
      permissions: ['read:own-profile', 'update:own-profile', 'delete:own-account'],
      description: 'Standard user with basic permissions',
    },
    {
      name: 'admin',
      permissions: [
        'read:own-profile',
        'update:own-profile',
        'read:all-users',
        'update:user-roles',
        'ban:users',
        'delete:users',
      ],
      description: 'Administrator with user management capabilities',
    },
    {
      name: 'super-admin',
      permissions: ['*'],
      description: 'Super administrator with all permissions',
    },
  ];

  for (const roleData of defaultRoles) {
    const existingRole = await Role.findOne({ name: roleData.name });
    if (!existingRole) {
      await Role.create(roleData);
    }
  }
};

const Role = mongoose.model<IRole>('Role', roleSchema);

export default Role;
