import mongoose from 'mongoose';
import logger from './logger';
import { env, isProduction } from './env';

/**
 * MongoDB connection configuration with pooling and error handling
 */
export const connectDatabase = async (): Promise<void> => {
  try {
    const options: mongoose.ConnectOptions = {
      maxPoolSize: env.mongodbPoolSize,
      minPoolSize: isProduction() ? 10 : 2,
      serverSelectionTimeoutMS: env.mongodbConnectionTimeout * 1000,
      socketTimeoutMS: 45000,
      family: 4, // Use IPv4
      autoIndex: env.mongodbAutoIndex,
    };

    await mongoose.connect(env.mongodbUri, options);

    logger.info(`MongoDB connected: ${mongoose.connection.host}`);
    logger.info(`Database name: ${mongoose.connection.name}`);
    logger.info(`Connection pool size: ${env.mongodbPoolSize.toString()}`);

    // Connection event listeners
    mongoose.connection.on('error', (error: Error) => {
      logger.error('MongoDB connection error:', error);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected');
    });

    mongoose.connection.on('reconnected', () => {
      logger.info('MongoDB reconnected');
    });

    // Handle process termination
    process.on('SIGINT', () => {
      void disconnectDatabase().then(() => process.exit(0));
    });

    process.on('SIGTERM', () => {
      void disconnectDatabase().then(() => process.exit(0));
    });
  } catch (error) {
    logger.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  }
};

/**
 * Gracefully disconnect from MongoDB
 */
export const disconnectDatabase = async (): Promise<void> => {
  try {
    await mongoose.connection.close();
    logger.info('MongoDB connection closed gracefully');
  } catch (error) {
    logger.error('Error closing MongoDB connection:', error);
    throw error;
  }
};

/**
 * Check if database is connected
 */
export const isDatabaseConnected = (): boolean => {
  return mongoose.connection.readyState === mongoose.ConnectionStates.connected;
};

/**
 * Get database connection status
 */
export const getDatabaseStatus = (): {
  state: string;
  host: string;
  name: string;
} => {
  const states = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  return {
    state: states[mongoose.connection.readyState] ?? 'unknown',
    host: mongoose.connection.host || 'N/A',
    name: mongoose.connection.name || 'N/A',
  };
};
