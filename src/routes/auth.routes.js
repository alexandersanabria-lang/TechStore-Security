const express = require('express');
const { register, login, me } = require('../controllers/auth.controller');
const { setupMfa, enableMfa, verifyMfa } = require('../controllers/mfa.controller');
const { verifyToken } = require('../middlewares/auth.middleware');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.get('/me', verifyToken, me);

// MFA
router.post('/mfa/setup', verifyToken, setupMfa);
router.post('/mfa/enable', verifyToken, enableMfa);
router.post('/mfa/verify', verifyMfa);

module.exports = router;