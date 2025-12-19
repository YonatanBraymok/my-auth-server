"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticateToken = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']; // Get the Authorization header
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    if (!token) { // If no token is provided, send unauthorized response
        res.status(401).json({ message: 'Access denied. No token provided' });
        return;
    }
    const SECRET_KEY = process.env.JWT_SECRET || 'default_secret';
    jsonwebtoken_1.default.verify(token, SECRET_KEY, (err, user) => {
        if (err) { // If token is invalid, send forbidden response
            res.status(403).json({ message: 'Invalid token' });
            return;
        }
        // Token is valid, proceed to the next middleware/route handler
        req.user = user;
        next();
    });
};
exports.authenticateToken = authenticateToken;
