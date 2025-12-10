import { type Request, type Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

/* ===============
* AUTHENTICATION MIDDLEWARE
*  =============== */
export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers['authorization']; // Get the Authorization header
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) { // If no token is provided, send unauthorized response
        res.status(401).json({ message: 'Access denied. No token provided' });
        return;
    }

    const SECRET_KEY = process.env.JWT_SECRET || 'default_secret';

    jwt.verify(token, SECRET_KEY, (err, user) => { // Verify the token
        if (err) { // If token is invalid, send forbidden response
            res.status(403).json({ message: 'Invalid token' });
            return;
        }

        // Token is valid, proceed to the next middleware/route handler
        next();
    });
};
