import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/user.model';
import crypto from 'crypto';
import { sendVerificationEmail, sendPasswordResetEmail } from '../services/email.service';

const generateRefreshToken = (userId: string) => {
    return jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET || 'refresh_default_secret', { expiresIn: '7d' });
};

export const refreshToken = async (req: Request, res: Response) => {
    const { token } = req.body;
    if (!token) {
        return res.status(401).json({ message: 'Refresh token is required' });
    }

    const refreshSecret = process.env.REFRESH_TOKEN_SECRET || 'refresh_default_secret';

    jwt.verify(token, refreshSecret, async (err: any, userPayload: any) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid refresh token' });
        }

        try {
            const user = await User.findById(userPayload.userId);
            if (!user || !user.refreshTokens || !user.refreshTokens.includes(token)) {
                return res.status(403).json({ message: 'Refresh token not recognized' });
            }

            const accessSecret = process.env.JWT_SECRET || 'default_secret';
            const newAccessToken = jwt.sign(
                { userId: user._id, email: user.email }, 
                accessSecret,
                { expiresIn: '15m' }
            );

            res.json({ accessToken: newAccessToken });
        } catch (error) {
            res.status(500).json({ message: 'Internal server error', error });
        }
    });
};

// Password validation function
const validatePassword = (password: string): string | null => {
    if (password.length < 8) return "Password must be at least 8 characters long";
    if (!/[A-Z]/.test(password)) return "Password must contain at least one uppercase letter";
    if (!/[a-z]/.test(password)) return "Password must contain at least one lowercase letter";
    if (!/[0-9]/.test(password)) return "Password must contain at least one digit";
    if (!/[!@#$%^&*]/.test(password)) return "Password must contain at least one special character (!@#$%^&*)";
    return null;
}

export const register = async (req: Request, res: Response) => {
    try {
        const { email, password, firstName, lastName, country, city } = req.body; // Destructure username and password from request body

        if (!email || !password || !firstName || !lastName || !country || !city) {
            res.status(400).json({ message: 'All fields are required!' });
            return;
        }

        const passwordError = validatePassword(password);
        if (passwordError) {
            res.status(400).json({ message: passwordError });
            return;
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            res.status(409).json({ message: 'User already exists' });
            return;
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = crypto.randomBytes(32).toString('hex'); // For Email Verification.

        const newUser = await User.create({
            email,
            firstName,
            lastName,
            country,
            city,
            password: hashedPassword,
            verificationToken,
            isVerified: false
        });

        try {
            await sendVerificationEmail(email, verificationToken);
        } catch (error) {
            console.error("Email send failed:", error);
        }

        res.status(201).json({ message: 'User registered successfully. Please check your email to verify your account.', userId: newUser._id });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Internal server error', error });
    }
};

export const login = async (req: Request, res: Response) => {
    try {
        const secret = process.env.JWT_SECRET || 'default_secret';
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            res.status(401).json({ message: 'User not found' });
            return;
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            res.status(401).json({ message: 'Wrong password' });
            return;
        }

        if (!user.isVerified) {
            res.status(403).json({ message: 'You must verify your email first!.'});
            return;
        }

        const accessToken = jwt.sign(
        { userId: user._id, email: user.email }, 
        process.env.JWT_SECRET || 'default_secret', 
        { expiresIn: '15m' } 
        );

        const refreshToken = generateRefreshToken(user._id as unknown as string);
        
        if (!user.refreshTokens) {
        user.refreshTokens = [];
        }
        user.refreshTokens.push(refreshToken);
        await user.save();

        res.json({ message: 'Login successful', accessToken, refreshToken });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error', error });
    }
};

export const logout = async (req: Request, res: Response) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ message: 'Refresh token is required' });
    }

    try {
        await User.findOneAndUpdate(
            { refreshTokens: token },
            { $pull: { refreshTokens: token } }
        );

        res.json({ message: 'Logouted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error', error });
    }
};

export const verifyEmail = async (req: Request, res: Response) => {
    const { token } = req.body;

    if (!token) {
        res.status(400).json({ message: 'Token is required' });
        return;
    }

    try {
        const user = await User.findOne({ verificationToken: token });

        if (!user) {
            res.status(400).json({ message: 'Invalid or expired token' });
            return;
        }

        user.isVerified = true;
        user.verificationToken = undefined as any;
        await user.save();

        res.status(200).json({ message: 'Email verified successfully!' });

    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
};

export const requestPasswordReset = async (req: Request, res: Response) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            // Apparently Gemini says this is a security trick to prevent account breach...
            // Meaning we say we sent an email to a non-existent account, even though we didnt.
            res.status(200).json({ message: 'Password reset request sent to this email!.' });
            return;
        }

        const resetToken = crypto.randomBytes(32).toString('hex');

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = new Date(Date.now() + 3600000) // 1 hour.

        await user.save();
        await sendPasswordResetEmail(user.email, resetToken);

        res.status(200).json({ message: 'Password reset request sent to this email!.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
};

export const resetPassword = async (req: Request, res: Response) => {
    const { token, newPassword } = req.body;

    try {
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            res.status(400).json({ message: 'Invalid or expired token' });
            return;
        }

        const passwordError = validatePassword(newPassword);
        if (passwordError) {
            res.status(400).json({ message: passwordError });
            return;
        }

        const isSamePassword = await bcrypt.compare(newPassword, user.password);
        if (isSamePassword) {
            res.status(400).json({ message: 'New password cannot be the same as the old password' });
            return;
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save();

        res.status(200).json({ message: 'Password has been reset successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
};