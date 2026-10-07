const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const jwt = require('jsonwebtoken');
const { users } = require('../data/store');
const { toPublicUser, generateToken } = require('./auth.controller');

const MAX_MFA_ATTEMPTS = 3;

function verifyTotp(secret, code) {
  return speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token: String(code),
    window: 1, // tolera 30 segundos de diferencia de reloj
  });
}

// ---------------------- PASO 1: generar secreto y QR (requiere token) ----------------------
async function setupMfa(req, res) {
  try {
    const user = users.find((u) => u.id === req.user.id);
    if (!user) {
      return res.status(404).json({ ok: false, mensaje: 'Usuario no encontrado' });
    }

    if (user.mfaEnabled) {
      return res.status(400).json({ ok: false, mensaje: 'El MFA ya está activado' });
    }

    const secret = speakeasy.generateSecret({
      length: 20,
      name: `TechStore (${user.email})`,
    });

    // Guardamos el secreto como "pendiente" hasta que el usuario confirme con un código
    user.mfaTempSecret = secret.base32;

    const qrCode = await QRCode.toDataURL(secret.otpauth_url);

    return res.json({
      ok: true,
      mensaje: 'Escanea el QR con Google Authenticator y luego confirma con /api/auth/mfa/enable',
      secret: secret.base32,
      qrCode,
    });
  } catch (error) {
    console.error('Error en setupMfa:', error);
    return res.status(500).json({ ok: false, mensaje: 'Error interno del servidor' });
  }
}

// ---------------------- PASO 2: confirmar y activar MFA (requiere token) ----------------------
function enableMfa(req, res) {
  const { code } = req.body;
  const user = users.find((u) => u.id === req.user.id);

  if (!user) {
    return res.status(404).json({ ok: false, mensaje: 'Usuario no encontrado' });
  }

  if (!user.mfaTempSecret) {
    return res.status(400).json({ ok: false, mensaje: 'Primero llama a /api/auth/mfa/setup' });
  }

  if (!code) {
    return res.status(400).json({ ok: false, mensaje: 'El código es obligatorio' });
  }

  if (!verifyTotp(user.mfaTempSecret, code)) {
    return res.status(401).json({ ok: false, mensaje: 'Código incorrecto' });
  }

  user.mfaSecret = user.mfaTempSecret;
  user.mfaTempSecret = null;
  user.mfaEnabled = true;

  return res.json({ ok: true, mensaje: 'MFA activado correctamente' });
}

// ---------------------- PASO 3: verificar código durante el login (público) ----------------------
function verifyMfa(req, res) {
  const { mfaToken, code } = req.body;

  if (!mfaToken || !code) {
    return res.status(400).json({ ok: false, mensaje: 'mfaToken y code son obligatorios' });
  }

  let payload;
  try {
    payload = jwt.verify(mfaToken, process.env.JWT_SECRET);
  } catch (error) {
    return res.status(401).json({ ok: false, mensaje: 'mfaToken inválido o expirado. Inicia sesión de nuevo' });
  }

  if (payload.purpose !== 'mfa') {
    return res.status(401).json({ ok: false, mensaje: 'Token no válido para MFA' });
  }

  const user = users.find((u) => u.id === payload.id);

  // La sesión MFA debe coincidir con la del último login
  if (!user || !user.mfaSession || user.mfaSession !== payload.sid) {
    return res.status(401).json({
      ok: false,
      mensaje: 'Sesión MFA no válida o agotada. Inicia sesión de nuevo',
    });
  }

  if (!verifyTotp(user.mfaSecret, code)) {
    user.mfaFailedAttempts += 1;

    if (user.mfaFailedAttempts >= MAX_MFA_ATTEMPTS) {
      user.mfaSession = null; // invalida el mfaToken: hay que volver a hacer login
      user.mfaFailedAttempts = 0;
      return res.status(423).json({
        ok: false,
        mensaje: `Superaste los ${MAX_MFA_ATTEMPTS} intentos. Debes iniciar sesión de nuevo`,
      });
    }

    return res.status(401).json({
      ok: false,
      mensaje: 'Código MFA incorrecto',
      intentosRestantes: MAX_MFA_ATTEMPTS - user.mfaFailedAttempts,
    });
  }

  // Código correcto: cerramos la sesión MFA y entregamos el token completo
  user.mfaSession = null;
  user.mfaFailedAttempts = 0;

  return res.json({
    ok: true,
    mensaje: 'Autenticación multifactor exitosa',
    token: generateToken(user),
    usuario: toPublicUser(user),
  });
}

module.exports = { setupMfa, enableMfa, verifyMfa };