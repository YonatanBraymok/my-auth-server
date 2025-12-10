import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/user.model';

/* ===============
* REGISTER ROUTE
*  =============== */ 
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

/* ===============
* LOGIN ROUTE
*  =============== */ 
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

        const token = jwt.sign({ userId: user._id, username: user.username }, secret, { expiresIn: '1h' });

        res.json({ message: 'Login successful', token });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error', error });
    }
};