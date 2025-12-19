"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config(); // Load environment variables from .env file
const cors_1 = __importDefault(require("cors"));
const express_1 = __importDefault(require("express"));
const db_1 = require("./config/db");
const auth_routes_1 = __importDefault(require("./routes/auth.routes"));
const auth_middleware_1 = require("./middleware/auth.middleware");
(0, db_1.connectDB)(); // Connect to the database
// Create an instance of an Express application
const app = (0, express_1.default)(); // Instance of a server. express(); is a Factory Pattern constructor
const PORT = process.env.PORT; // Use the PORT from environment variables
app.use((0, cors_1.default)()); // Enable CORS for all routes
// Define the server can use JSON
app.use(express_1.default.json()); // Middleware to parse JSON bodies
app.use('/api/auth', auth_routes_1.default); // Use authentication routes under /api/auth
// Example of a protected route
app.get('/api/private', auth_middleware_1.authenticateToken, (req, res) => {
    res.json({ message: 'This is private data!', secret: 'Shhh' });
});
// Start the server and listen on the specified port
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
