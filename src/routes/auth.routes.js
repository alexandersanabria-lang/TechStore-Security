const express = require('express');
const passport = require('../config/passport');
const { register, login, me } = require('../controllers/auth.controller');
const { setupMfa, enableMfa, verifyMfa } = require('../controllers/mfa.controller');
const { socialCallback, socialError } = require('../controllers/social.controller');
const { verifyToken } = require('../middlewares/auth.middleware');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/me', verifyToken, me);

// MFA
router.post('/mfa/setup', verifyToken, setupMfa);
router.post('/mfa/enable', verifyToken, enableMfa);
router.post('/mfa/verify', verifyMfa);

// Login social: Google
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'], session: false }));
router.get(
  '/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/api/auth/social/error' }),
  socialCallback
);

// Login social: GitHub
router.get('/github', passport.authenticate('github', { scope: ['user:email'], session: false }));
router.get(
  '/github/callback',
  passport.authenticate('github', { session: false, failureRedirect: '/api/auth/social/error' }),
  socialCallback
);

router.get('/social/error', socialError);

module.exports = router;