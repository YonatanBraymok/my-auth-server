import express from 'express';
import authRoutes from './routes/auth.routes';
import { authenticateToken } from './middleware/auth.middleware';

// Create an instance of an Express application
const app = express(); // Instance of a server. express(); is a Factory Pattern constructor
const PORT = 3000;

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