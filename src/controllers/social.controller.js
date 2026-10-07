const crypto = require('crypto');
const { toPublicUser, generateToken, generateMfaToken } = require('./auth.controller');

// Se ejecuta cuando Google/GitHub confirman la identidad
function socialCallback(req, res) {
  const user = req.user;

  // Si tiene MFA activado, también debe pasar por el segundo factor
  if (user.mfaEnabled) {
    const sid = crypto.randomUUID();
    user.mfaSession = sid;
    user.mfaFailedAttempts = 0;
    return res.json({
      ok: true,
      mfaRequired: true,
      mensaje: 'Login social correcto. Ingresa tu código en /api/auth/mfa/verify',
      mfaToken: generateMfaToken(user, sid),
    });
  }

  return res.json({
    ok: true,
    mensaje: `Inicio de sesión con ${user.provider} exitoso`,
    token: generateToken(user),
    usuario: toPublicUser(user),
  });
}

function socialError(req, res) {
  res.status(401).json({ ok: false, mensaje: 'Falló el inicio de sesión social' });
}

module.exports = { socialCallback, socialError };