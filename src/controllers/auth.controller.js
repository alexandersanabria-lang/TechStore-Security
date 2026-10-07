const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { users, nextId } = require('../data/store');
const { isValidEmail, validatePassword } = require('../utils/validators');

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_MINUTES = Number(process.env.LOCK_MINUTES) || 15;

// Quita datos sensibles antes de responder
function toPublicUser(user) {
  return {
    id: user.id,
    email: user.email,
    fullName: user.fullName,
    store: user.store,
    role: user.role,
    mfaEnabled: user.mfaEnabled,
    createdAt: user.createdAt,
  };
}

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

// Token temporal que solo sirve para completar el paso MFA
function generateMfaToken(user, sid) {
  return jwt.sign(
    { id: user.id, purpose: 'mfa', sid },
    process.env.JWT_SECRET,
    { expiresIn: '5m' }
  );
}

// ---------------------- REGISTRO ----------------------
async function register(req, res) {
  try {
    const { email, password, fullName, store } = req.body;

    if (!email || !password || !fullName || !store) {
      return res.status(400).json({
        ok: false,
        mensaje: 'Todos los campos son obligatorios: email, password, fullName, store',
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ ok: false, mensaje: 'El email no tiene un formato válido' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    if (users.some((u) => u.email === normalizedEmail)) {
      return res.status(409).json({ ok: false, mensaje: 'Ese email ya está registrado' });
    }

    const passwordErrors = validatePassword(password);
    if (passwordErrors.length > 0) {
      return res.status(400).json({
        ok: false,
        mensaje: 'La contraseña no cumple los requisitos',
        errores: passwordErrors,
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const newUser = {
      id: nextId(),
      email: normalizedEmail,
      passwordHash,
      fullName: fullName.trim(),
      store: store.trim(),
      role: 'ventas',
      failedAttempts: 0,
      lockUntil: null,
      mfaEnabled: false,
      mfaSecret: null,
      mfaTempSecret: null,
      mfaSession: null,
      mfaFailedAttempts: 0,
      createdAt: new Date().toISOString(),
    };

    users.push(newUser);

    return res.status(201).json({
      ok: true,
      mensaje: 'Usuario registrado correctamente',
      usuario: toPublicUser(newUser),
    });
  } catch (error) {
    console.error('Error en register:', error);
    return res.status(500).json({ ok: false, mensaje: 'Error interno del servidor' });
  }
}

// ---------------------- LOGIN ----------------------
async function login(req, res) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ ok: false, mensaje: 'Email y password son obligatorios' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const user = users.find((u) => u.email === normalizedEmail);

    // Mensaje genérico: no revelamos si el email existe o no
    if (!user) {
      return res.status(401).json({ ok: false, mensaje: 'Credenciales inválidas' });
    }

    // 1. ¿La cuenta está bloqueada?
    if (user.lockUntil && Date.now() < user.lockUntil) {
      const minutosRestantes = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({
        ok: false,
        mensaje: `Cuenta bloqueada por demasiados intentos fallidos. Intenta de nuevo en ${minutosRestantes} minuto(s)`,
      });
    }

    // 2. Si el bloqueo ya venció, limpiamos el estado
    if (user.lockUntil && Date.now() >= user.lockUntil) {
      user.lockUntil = null;
      user.failedAttempts = 0;
    }

    // 3. Validar contraseña
    const passwordOk = await bcrypt.compare(password, user.passwordHash);

    if (!passwordOk) {
      user.failedAttempts += 1;

      if (user.failedAttempts >= MAX_FAILED_ATTEMPTS) {
        user.lockUntil = Date.now() + LOCK_MINUTES * 60 * 1000;
        user.failedAttempts = 0;
        return res.status(423).json({
          ok: false,
          mensaje: `Cuenta bloqueada por ${LOCK_MINUTES} minuto(s) tras ${MAX_FAILED_ATTEMPTS} intentos fallidos`,
        });
      }

      const restantes = MAX_FAILED_ATTEMPTS - user.failedAttempts;
      return res.status(401).json({
        ok: false,
        mensaje: 'Credenciales inválidas',
        intentosRestantes: restantes,
      });
    }

    // 4. Contraseña correcta: reiniciamos contador
    user.failedAttempts = 0;
    user.lockUntil = null;

    // 5. Si tiene MFA activado, NO entregamos el token final todavía
    if (user.mfaEnabled) {
      const sid = crypto.randomUUID();
      user.mfaSession = sid;
      user.mfaFailedAttempts = 0;

      return res.status(200).json({
        ok: true,
        mfaRequired: true,
        mensaje: 'Credenciales correctas. Ingresa el código de tu app autenticadora en /api/auth/mfa/verify',
        mfaToken: generateMfaToken(user, sid),
      });
    }

    // 6. Sin MFA: token completo
    return res.status(200).json({
      ok: true,
      mensaje: 'Inicio de sesión exitoso',
      token: generateToken(user),
      usuario: toPublicUser(user),
    });
  } catch (error) {
    console.error('Error en login:', error);
    return res.status(500).json({ ok: false, mensaje: 'Error interno del servidor' });
  }
}

// ---------------------- PERFIL (ruta protegida) ----------------------
function me(req, res) {
  const user = users.find((u) => u.id === req.user.id);

  if (!user) {
    return res.status(404).json({ ok: false, mensaje: 'Usuario no encontrado' });
  }

  return res.json({ ok: true, usuario: toPublicUser(user) });
}

module.exports = { register, login, me, toPublicUser, generateToken };