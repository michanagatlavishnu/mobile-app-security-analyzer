const bcrypt = require('bcryptjs');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

const PASSWORD_REGEX = /^(?=.*[A-Za-z])(?=.*\d).{8,}$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Get User Profile
 * GET /api/users/profile
 */
async function getProfile(req, res, next) {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User profile not found',
      });
    }

    return res.status(200).json({
      success: true,
      user,
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Update User Profile
 * PUT /api/users/profile
 */
async function updateProfile(req, res, next) {
  try {
    const { name, email } = req.body;
    const userId = req.user.userId;

    if (!name || name.trim().length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Name is required',
      });
    }

    if (!email || !EMAIL_REGEX.test(email.trim())) {
      return res.status(400).json({
        success: false,
        message: 'A valid email is required',
      });
    }

    // Check if new email is taken by another account
    const existing = await User.findByEmail(email.trim());
    if (existing && existing.id !== userId) {
      return res.status(409).json({
        success: false,
        message: 'This email is already in use by another account',
      });
    }

    const updatedUser = await User.updateUser(userId, {
      name: name.trim(),
      email: email.trim(),
    });

    await AuditLog.log({
      userId,
      action: 'USER_PROFILE_UPDATED',
      ipAddress: req.ip,
    });

    return res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      user: updatedUser,
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Change Password
 * PUT /api/users/change-password
 */
async function changePassword(req, res, next) {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.userId;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Both current password and new password are required',
      });
    }

    if (!PASSWORD_REGEX.test(newPassword)) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 8 characters long and contain both letters and numbers',
      });
    }

    // 1. Fetch user with current password hash
    const user = await User.findByIdWithPassword(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User account not found',
      });
    }

    // 2. Verify current password
    const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: 'Current password provided is incorrect',
      });
    }

    // 3. Hash new password
    const salt = await bcrypt.genSalt(10);
    const newPasswordHash = await bcrypt.hash(newPassword, salt);

    // 4. Update in database
    await User.updatePassword(userId, newPasswordHash);

    // 5. Log audit event
    await AuditLog.log({
      userId,
      action: 'PASSWORD_CHANGED',
      ipAddress: req.ip,
    });

    logger.info(`Password successfully changed for user ID: ${userId}`);

    return res.status(200).json({
      success: true,
      message: 'Password changed successfully',
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  getProfile,
  updateProfile,
  changePassword,
};
