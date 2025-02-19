import jwt from 'jsonwebtoken';
export const authenticateToken = (req, res, next) => {
    // The token is expected in the Authorization header as "Bearer <token>"
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.sendStatus(401); // Unauthorized if no token provided
    }
    jwt.verify(token, process.env.JWT_SECRET_KEY || 'defaultsecret', (err, decoded) => {
        if (err) {
            return res.sendStatus(403); // Forbidden if token is invalid
        }
        // Attach the decoded payload (cast to JwtPayload) to the request object
        req.user = decoded;
        return next(); // Explicit return helps TypeScript verify that all code paths return a value
    });
};
