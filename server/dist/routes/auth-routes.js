import { Router } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
export const login = async (req, res) => {
    const { username, password } = req.body;
    // Check that username and password are provided
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }
    try {
        // Find the user by username (adjust query as needed for your ORM)
        const user = await User.findOne({ where: { username } });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }
        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }
        // Create a JWT payload. You can include additional user data as needed.
        const payload = { username: user.username, id: user.id };
        // Sign the JWT token. Make sure to set JWT_SECRET_KEY in your environment.
        const token = jwt.sign(payload, process.env.JWT_SECRET_KEY || 'defaultsecret', { expiresIn: '1h' });
        // Return the token in the response
        return res.json({ token });
    }
    catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ error: 'Internal server error.' });
    }
};
const router = Router();
// POST /login - Login a user
router.post('/login', login);
export default router;
