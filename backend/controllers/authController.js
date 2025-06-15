const User = require('../models/User');
const { generateToken } = require('../middleware/auth');
const jwt = require('jsonwebtoken');

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    const userExists = await User.findOne({ email });

    if (userExists) {
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email',
      });
    }

    // Create user
    const user = await User.create({
      name,
      email,
      password,
    });

    if (user) {
      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: {
          _id: user._id,
          name: user.name,
          email: user.email,
          currency: user.currency,
          theme: user.theme,
          avatar: user.avatar,
          token: generateToken(user._id),
        },
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Invalid user data',
      });
    }
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during registration',
    });
  }
};

// @desc    Authenticate user & get token
// @route   POST /api/auth/login
// @access  Public
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check for user email
    const user = await User.findOne({ email }).select('+password');

    if (user && (await user.matchPassword(password))) {
      res.json({
        success: true,
        message: 'Login successful',
        data: {
          _id: user._id,
          name: user.name,
          email: user.email,
          currency: user.currency,
          theme: user.theme,
          avatar: user.avatar,
          token: generateToken(user._id),
        },
      });
    } else {
      res.status(401).json({
        success: false,
        message: 'Invalid email or password',
      });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login',
    });
  }
};

// @desc    Get user profile
// @route   GET /api/auth/profile
// @access  Private
const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (user) {
      res.json({
        success: true,
        data: {
          _id: user._id,
          name: user.name,
          email: user.email,
          currency: user.currency,
          theme: user.theme,
          avatar: user.avatar,
          isEmailVerified: user.isEmailVerified,
          createdAt: user.createdAt,
        },
      });
    } else {
      res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while fetching profile',
    });
  }
};

// @desc    Update user profile
// @route   PUT /api/auth/profile
// @access  Private
const updateProfile = async (req, res) => {
  try {
    const { name, currency, theme, avatar } = req.body;

    const user = await User.findById(req.user.id);

    if (user) {
      user.name = name || user.name;
      user.currency = currency || user.currency;
      user.theme = theme || user.theme;
      user.avatar = avatar || user.avatar;

      const updatedUser = await user.save();

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: {
          _id: updatedUser._id,
          name: updatedUser.name,
          email: updatedUser.email,
          currency: updatedUser.currency,
          theme: updatedUser.theme,
          avatar: updatedUser.avatar,
        },
      });
    } else {
      res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while updating profile',
    });
  }
};

// @desc    Change password
// @route   PUT /api/auth/change-password
// @access  Private
const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.user.id).select('+password');

    if (user && (await user.matchPassword(currentPassword))) {
      user.password = newPassword;
      await user.save();

      res.json({
        success: true,
        message: 'Password changed successfully',
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Current password is incorrect',
      });
    }
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while changing password',
    });
  }
};

// @desc    OAuth success callback
// @route   GET /api/auth/oauth/success
// @access  Public (but requires OAuth authentication)
const oauthSuccess = async (req, res) => {
  try {
    console.log('🔍 OAuth Success - CLIENT_URL:', process.env.CLIENT_URL);

    if (!req.user) {
      console.log('❌ No user found in OAuth callback');
      return res.redirect(`${process.env.CLIENT_URL}/login?error=oauth_failed`);
    }

    // Generate JWT token for the OAuth user
    const token = generateToken(req.user._id);
    const redirectUrl = `${process.env.CLIENT_URL}/oauth/callback?token=${token}`;

    console.log('✅ OAuth Success - Redirecting to:', redirectUrl);
    console.log('👤 User:', req.user.email);

    // Redirect to frontend with token
    res.redirect(redirectUrl);
  } catch (error) {
    console.error('OAuth success error:', error);
    res.redirect(`${process.env.CLIENT_URL}/login?error=oauth_error`);
  }
};

// @desc    OAuth failure callback
// @route   GET /api/auth/oauth/failure
// @access  Public
const oauthFailure = (req, res) => {
  res.redirect(`${process.env.CLIENT_URL}/login?error=oauth_failed`);
};

module.exports = {
  register,
  login,
  getProfile,
  updateProfile,
  changePassword,
  oauthSuccess,
  oauthFailure,
};
