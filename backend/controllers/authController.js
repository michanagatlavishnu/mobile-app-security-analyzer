const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const env = require('../config/env');
const logger = require('../utils/logger');

// Password complexity regex: at least 8 chars, at least 1 letter and 1 number
const PASSWORD_REGEX = /^(?=.*[A-Za-z])(?=.*\d).{8,}$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Register a new user
 * POST /api/auth/register
 */
async function register(req, res, next) {
  try {
    const { name, email, password } = req.body;

    // 1. Validation
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Full name is required',
      });
    }

    if (!email || !EMAIL_REGEX.test(email.trim())) {
      return res.status(400).json({
        success: false,
        message: 'A valid email address is required',
      });
    }

    if (!password || !PASSWORD_REGEX.test(password)) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long and contain both letters and numbers',
      });
    }

    // 2. Check for duplicate email
    const existing = await User.findByEmail(email);
    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'An account with this email address already exists',
      });
    }

    // 3. Hash password using bcrypt (10 rounds)
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // 4. Create user in database
    const newUser = await User.createUser({
      name: name.trim(),
      email: email.trim(),
      passwordHash,
      role: 'user',
    });

    // 5. Generate initial session JWT token
    const token = jwt.sign(
      { userId: newUser.id, role: newUser.role },
      env.jwtSecret,
      { expiresIn: env.jwtExpiresIn }
    );

    // 6. Log audit event
    await AuditLog.log({
      userId: newUser.id,
      action: 'USER_REGISTERED',
      ipAddress: req.ip,
    });

    logger.info(`New user registered: ${newUser.email} (ID: ${newUser.id})`);

    // Never return password_hash
    return res.status(201).json({
      success: true,
      message: 'Registration successful',
      token,
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * User Login
 * POST /api/auth/login
 */
async function login(req, res, next) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required',
      });
    }

    // 1. Fetch user by email
    const user = await User.findByEmail(email);
    if (!user) {
      // Use generic error message to prevent account enumeration
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
    }

    // 2. Verify password with bcrypt
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      logger.warn(`Failed login attempt for email: ${email}`, { ip: req.ip });
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
    }

    // Check account status
    if (user.status && user.status !== 'active') {
      logger.warn(`Login rejected for disabled account: ${email}`, { ip: req.ip, status: user.status });
      return res.status(403).json({
        success: false,
        message: 'Account is disabled. Please contact an administrator.',
      });
    }

    // 3. Generate JWT payload containing only necessary public claims
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      env.jwtSecret,
      { expiresIn: env.jwtExpiresIn }
    );

    // 4. Update last_login timestamp & log audit event
    await User.updateLastLogin(user.id);
    await AuditLog.log({
      userId: user.id,
      action: 'USER_LOGIN',
      ipAddress: req.ip,
    });

    logger.info(`User logged in successfully: ${user.email} (ID: ${user.id})`);

    return res.status(200).json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Get Current Authenticated User Profile
 * GET /api/auth/me
 */
async function getCurrentUser(req, res, next) {
  try {
    const userId = req.user.userId;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User account not found',
      });
    }

    return res.status(200).json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        createdAt: user.created_at,
        updatedAt: user.updated_at,
      },
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  register,
  login,
  getCurrentUser,
};
