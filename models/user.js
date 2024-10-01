import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';


const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  roles: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Role' }],  // Reference to Role model
  permissions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Permission' }]  // Reference to Permission model
});


const roleSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  permissions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Permission' }]
});

export const Role = mongoose.model('Role', roleSchema);


const permissionSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },  // e.g., "read", "write", "delete"
  description: { type: String }  // A short description of the permission
});

export const Permission = mongoose.model('Permission', permissionSchema);


userSchema.pre('save', async function (next) {
  if (this.isModified('password') || this.isNew) {
    const hashedPassword = await bcrypt.hash(this.password, 10);
    this.password = hashedPassword;
  }
  next();
});

userSchema.methods.authenticate = async function (password) {
  const isMatch = await bcrypt.compare(password, this.password);
  if (!isMatch) {
    throw new Error('Invalid credentials');
  }

  await this.populate('roles permissions').execPopulate();

  const token = jwt.sign(
    {
      id: this._id,
      roles: this.roles.map(role => role.name),  // Store role names in token
      permissions: this.permissions.map(permission => permission.name)  // Store permission names in token
    },
    'your-secret-key',
    { expiresIn: '1h' }  
  );

  return token;
};

userSchema.statics.register = async function (username, password) {
  const user = new this({ username, password, roles: [], permissions: [] });
  await user.save();
  return user;
};

userSchema.methods.hasAccess = async function (requiredRoles = [], requiredPermissions = []) {
  await this.populate('roles permissions').execPopulate();

  const hasRole = requiredRoles.some(role =>
    this.roles.map(r => r.name).includes(role)
  );
  const hasPermission = requiredPermissions.some(permission =>
    this.permissions.map(p => p.name).includes(permission)
  );

  return hasRole || hasPermission;
};

// User model
const User = mongoose.model('User', userSchema);
export default User;
