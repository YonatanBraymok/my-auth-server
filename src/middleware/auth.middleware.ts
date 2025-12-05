import express, { type Request, type Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// In a real app, we never store the tokens or passwords in plain text, this is just for demonstration purposes!
const SECRET_KEY = "your_secret_key"; // Secret key for JWT signing

/* ===============
* AUTHENTICATION MIDDLEWARE
*  =============== */
export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization']; // Get the Authorization header
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) { // If no token is provided, send unauthorized response
        res.sendStatus(401).json({ message: 'Access denied. No token provided' });
        return;
    }

    jwt.verify(token, SECRET_KEY, (err, user) => { // Verify the token
        if (err) { // If token is invalid, send forbidden response
            res.sendStatus(403).json({ message: 'Invalid token' });
            return;
        }

        // Token is valid, proceed to the next middleware/route handler
        next();
    });
};
