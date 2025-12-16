import nodemailer from 'nodemailer';

// Configure the email transporter (will be changed to use real SMTP in production)
const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
        user: 'deion.greenfelder@ethereal.email',
        pass: 'k6RwQVS7dPnQzZDTgh',
    },
});

export const sendVerificationEmail = async (toEmail: string, verificationToken: string) => {
    // Create verification link
    const link = `http://localhost:5173/verify?token=${verificationToken}`;

    const info = await transporter.sendMail({
        from: '"My Auth App" <no-reply@auth-app.com>',
        to: toEmail,
        subject: "Verify your email",
        html: `
        <h3>Welcome!</h3>
        <p>Please click the link below to verify your email address:</p>
        <a href="${link}">Verify Email</a>
        `,
    });

    console.log('Verification email sent: %s', info.messageId);
    console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
};

export const sendPasswordResetEmail = async (toEmail: string, resetToken: string) => {
    const link = `http://localhost:5173/reset-password?token=${resetToken}`;

    const info = await transporter.sendMail({
        from: '"My Auth App" <no-reply@auth-app.com>',
        to: toEmail,
        subject: "Password Reset Request",
        html: `
        <h3>Password Reset</h3>
        <p>You requested to reset your password.</p>
        <p>Click the link below to set a new password:</p>
        <a href="${link}">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
        `,
    });

    console.log("Reset Email sent: %s", info.messageId);
    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
}
