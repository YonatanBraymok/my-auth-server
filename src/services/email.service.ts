import { Resend } from 'resend';
import dotenv from 'dotenv';

dotenv.config;

const resend = new Resend(process.env.RESEND_API_KEY);
const fromEmail = process.env.FROM_EMAIL || 'onboarding@resend.dev';

export const sendVerificationEmail = async (toEmail: string, verificationToken: string) => {
    const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
    const link = `${clientUrl}/verify?token=${verificationToken}`;

    try {
    const { data,error } = await resend.emails.send({
      from: fromEmail, 
      to: toEmail,
      subject: 'Verify your email',
      html: `
        <h3>Welcome!</h3>
        <p>Please click the link below to verify your email address:</p>
        <a href="${link}">Verify Email</a>
      `
    });

    if (error) {
        console.error("Resend error: ", error);
        return;
    }

  } catch (err) {
    console.error("Unexpected Error:", err);
  }
};

export const sendPasswordResetEmail = async (toEmail: string, resetToken: string) => {
  const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
  const link = `${clientUrl}/reset-password?token=${resetToken}`;

  try {
    const { data, error } = await resend.emails.send({
      from: fromEmail,
      to: toEmail,
      subject: 'Password Reset Request',
      html: `
        <h3>Password Reset</h3>
        <p>Click the link below to set a new password:</p>
        <a href="${link}">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
      `
    });

    if (error) {
        console.error("Resend error: ", error);
        return;
    }

    console.log("Reset email sent successfully. ID:", data?.id);
  } catch (err) {
    console.error("Unexpected error:", err);
  }
};
