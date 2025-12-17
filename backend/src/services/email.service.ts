import { Resend } from 'resend';
import { env } from '@config/env';
import logger from '@config/logger';

const resendClient = new Resend(env.resendApiKey);

const buildFromAddress = (): string => {
  if (env.resendFromEmail) {
    return `${env.resendFromName} <${env.resendFromEmail}>`;
  }
  return env.emailFrom;
};

interface EmailContent {
  subject: string;
  text: string;
  html: string;
}

const renderVerificationTemplate = (verificationUrl: string, token: string): EmailContent => ({
  subject: 'Verify your email',
  text: [
    'Welcome to MERN Auth!',
    '',
    'Please verify your email by visiting the following link:',
    verificationUrl,
    '',
    'If you did not sign up, you can ignore this email.',
    '',
    `Your verification token (paste if needed): ${token}`,
  ].join('\n'),
  html: [
    '<h1>Welcome to MERN Auth</h1>',
    '<p>Please verify your email by clicking the link below:</p>',
    `<p><a href="${verificationUrl}">Verify email</a></p>`,
    '<p>If the button does not work, copy and paste this URL:</p>',
    `<p>${verificationUrl}</p>`,
    `<p>Token: <code>${token}</code></p>`,
  ].join(''),
});

const renderPasswordResetTemplate = (resetUrl: string, token: string): EmailContent => ({
  subject: 'Reset your password',
  text: [
    'Password reset requested',
    '',
    'Use the link below to reset your password:',
    resetUrl,
    '',
    `Reset token (paste if needed): ${token}`,
    '',
    'If you did not request this, you can safely ignore this email.',
  ].join('\n'),
  html: [
    '<h1>Password reset requested</h1>',
    '<p>Use the link below to reset your password:</p>',
    `<p><a href="${resetUrl}">Reset password</a></p>`,
    '<p>If the button does not work, copy and paste this URL:</p>',
    `<p>${resetUrl}</p>`,
    `<p>Token: <code>${token}</code></p>`,
    '<p>If you did not request this, you can safely ignore this email.</p>',
  ].join(''),
});

const renderPasswordChangedTemplate = (): EmailContent => ({
  subject: 'Your password was changed',
  text: [
    'Your password was changed',
    '',
    'If you made this change, no action is needed.',
    'If you did not make this change, please reset your password immediately.',
  ].join('\n'),
  html: [
    '<h1>Your password was changed</h1>',
    '<p>If you made this change, no action is needed.</p>',
    '<p>If you did not make this change, please reset your password immediately.</p>',
  ].join(''),
});

const renderWelcomeTemplate = (): EmailContent => ({
  subject: 'Welcome to MERN Auth',
  text: [
    'Welcome aboard!',
    '',
    'Your email has been verified successfully.',
    'You can now sign in and continue.',
  ].join('\n'),
  html: [
    '<h1>Welcome aboard!</h1>',
    '<p>Your email has been verified successfully.</p>',
    '<p>You can now sign in and continue.</p>',
  ].join(''),
});

const sendEmail = async (to: string, content: EmailContent): Promise<void> => {
  if (!env.resendApiKey) {
    logger.warn(
      `Resend API key is not configured; skipping email send for subject: ${content.subject}`
    );
    return;
  }

  try {
    await resendClient.emails.send({
      from: buildFromAddress(),
      to,
      subject: content.subject,
      text: content.text,
      html: content.html,
    });
  } catch (error) {
    logger.error(`Failed to send email (${content.subject})`, error as Error);
    throw error;
  }
};

export const sendVerificationEmail = async (email: string, token: string): Promise<void> => {
  const verificationUrl = `${env.frontendUrl}/verify-email?token=${token}`;
  const content = renderVerificationTemplate(verificationUrl, token);
  await sendEmail(email, content);
};

export const sendPasswordResetEmail = async (email: string, token: string): Promise<void> => {
  const resetUrl = `${env.frontendUrl}/reset-password?token=${token}`;
  const content = renderPasswordResetTemplate(resetUrl, token);
  await sendEmail(email, content);
};

export const sendPasswordChangedEmail = async (email: string): Promise<void> => {
  const content = renderPasswordChangedTemplate();
  await sendEmail(email, content);
};

export const sendWelcomeEmail = async (email: string): Promise<void> => {
  const content = renderWelcomeTemplate();
  await sendEmail(email, content);
};
