import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import { connectDB } from './config/db';
import authRoutes from './routes/auth.routes';
import { authenticateToken } from './middleware/auth.middleware';

dotenv.config(); // Load environment variables from .env file
connectDB(); // Connect to the database

// Create an instance of an Express application
const app = express(); // Instance of a server. express(); is a Factory Pattern constructor
const PORT = process.env.PORT; // Use the PORT from environment variables

app.use(cors()); // Enable CORS for all routes

// Define the server can use JSON
app.use(express.json()); // Middleware to parse JSON bodies

app.use('/api/auth', authRoutes); // Use authentication routes under /api/auth

// Example of a protected route
app.get('/api/private', authenticateToken, (req, res) => {
  res.json({ message: 'This is private data!', secret: 'Shhh' });
});

// Start the server and listen on the specified port
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});