const express = require('express');
const passport = require('passport');
const {
  register,
  login,
  getProfile,
  updateProfile,
  changePassword,
  oauthSuccess,
  oauthFailure,
} = require('../controllers/authController');
const { protect } = require('../middleware/auth');
const {
  validateRegister,
  validateLogin,
} = require('../middleware/validation');

const router = express.Router();

// Public routes
router.post('/register', validateRegister, register);
router.post('/login', validateLogin, login);

// Protected routes
router.get('/profile', protect, getProfile);
router.put('/profile', protect, updateProfile);
router.put('/change-password', protect, changePassword);

// OAuth routes
// Google OAuth
router.get('/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/google/callback',
  passport.authenticate('google', { failureRedirect: '/api/auth/oauth/failure' }),
  oauthSuccess
);

// Microsoft OAuth - REMOVED (keeping only Google OAuth)

// OAuth callback routes
router.get('/oauth/success', oauthSuccess);
router.get('/oauth/failure', oauthFailure);

module.exports = router;
