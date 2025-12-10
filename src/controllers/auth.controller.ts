import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/user.model';

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
                { userId: user._id, username: user.username }, 
                accessSecret,
                { expiresIn: '15m' }
            );

            res.json({ accessToken: newAccessToken });
        } catch (error) {
            res.status(500).json({ message: 'Internal server error', error });
        }
    });
};
        

export const register = async (req: Request, res: Response) => {
    try {
        const { username, password } = req.body; // Destructure username and password from request body

        if (!username || !password) {
            res.status(400).send('Username and password are required');
            return;
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            res.status(409).send('Username already exists');
            return;
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            username,
            password: hashedPassword
        });

        res.status(201).json({ message: 'User registered successfully', userId: newUser._id });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Internal server error', error });
    }
};

export const login = async (req: Request, res: Response) => {
    try {
        const secret = process.env.JWT_SECRET || 'default_secret';
        const { username, password } = req.body;

         const user = await User.findOne({ username });
        if (!user) {
            res.status(401).send('Invalid username');
            return;
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            res.status(401).send('Invalid password');
            return;
        }

        const accessToken = jwt.sign(
        { userId: user._id, username: user.username }, 
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