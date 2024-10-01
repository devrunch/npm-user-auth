import jwt from 'jsonwebtoken';
import User from '../models/user';  // Adjust the path based on your file structure

// Authorization middleware
const authorize = (requiredRoles = [], requiredPermissions = []) => {
    return async (req, res, next) => {
        try {
            // Get token from authorization header
            const token = req.headers.authorization?.split(' ')[1];
            if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

            // Verify the token
            const decoded = jwt.verify(token, 'your-secret-key');

            // Find the user by decoded token ID
            const user = await User.findById(decoded.id);
            if (!user) return res.status(404).json({ error: 'User not found.' });

            if (requiredRoles.length === 0 && requiredPermissions.length === 0) {
                req.user = user;
                return next();
            }
            // Check if the user has access based on roles or permissions
            const hasAccess = await user.hasAccess(requiredRoles, requiredPermissions);
            if (!hasAccess) {
                return res.status(403).json({ error: 'Forbidden. You do not have access to this resource.' });
            }

            // If everything is good, proceed to the next middleware or route handler
            req.user = user;
            next();
        } catch (error) {
            // Handle any errors, such as token expiration or invalid token
            return res.status(401).json({ error: 'Invalid or expired token.' });
        }
    };
};

export default authorize;
