import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { users, User } from '../models/user.model';

const SECRET_KEY = "your_secret_key"; // Secret key for JWT signing

/* ===============
* REGISTER ROUTE
*  =============== */ 
export const register = async (req: Request, res: Response) => {
    const { username, password } = req.body; // Destructure username and password from request body

    // Basic validation
    if (!username || !password) {
        res.status(400).send('Username and password are required');
        return;
    }

    // Check if user already exists in the in-memory array
    const userExists = users.find(user => user.username === username);
    if (userExists) { // If user already exists, send a conflict response
        res.status(409).send('User already exists');
        return;
    }

    // Hash the password before storing (in a real app)
    const hashedPassword = await bcrypt.hash(password, 10); // Hash password with salt rounds = 10
    const newUser: User = { username, password: hashedPassword }; // Create new user with hashed password
    users.push(newUser);

    console.log('Registered users:', users); // Log the current users for debugging

    res.status(201).send('User registered successfully'); // Send success response
};

/* ===============
* LOGIN ROUTE
*  =============== */ 
export const login = async (req: Request, res: Response) => {
    const { username, password } = req.body; // Destructure username and password from request body
    
    // Basic validation
    if (!username || !password) {
        res.status(400).send('Username and password are required');
        return;
    }
    
    // Find user in the in-memory array
    const user = users.find(user => user.username === username);
    if (!user) { // If user not found, send unauthorized response
        res.status(401).send('Invalid username or password');
        return;
    }
    
    // Compare provided password with stored hashed password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) { // If passwords do not match, send unauthorized response
        res.status(401).send('Invalid username or password');
        return;
    }

    // Generate JWT token
    const token = jwt.sign(
        { username: user.username }, // Payload
        SECRET_KEY,                 // Secret key
        { expiresIn: '1h' }         // Options
    )

    // Send success response with JWT token
    res.status(200).json({
        message: 'Login successful',
        token: token
    });
};