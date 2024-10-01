import User  from '../models/user';

// Register a new user
const register = async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.register(username, password);
    res.status(201).send(user);
  } catch (err) {
    res.status(400).send(err.message);
  }
};

// Login user and generate a token
const login = async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) throw new Error('User not found');

    const token = await user.authenticate(password);
    res.send({ token });
  } catch (err) {
    res.status(401).send(err.message);
  }
};

// Check user access for protected routes
const checkAccess = async (req, res, next, requiredRoles = [], requiredPermissions = []) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('Access Denied');

  try {
    const decoded = jwt.verify(token, 'your-secret-key');
    const user = await User.findById(decoded.id);
    if (!user) return res.status(401).send('Invalid token');

    if (requiredRoles.length === 0 && requiredPermissions.length === 0) {
      return next();
    }
    if (!user.hasAccess(requiredRoles, requiredPermissions)) {
      return res.status(403).send('Forbidden');
    }

    next();
  } catch (err) {
    res.status(401).send('Invalid token');
  }
};

module.exports = { register, login, checkAccess };
