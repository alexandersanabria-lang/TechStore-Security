const bcrypt = require('bcryptjs');
const { users, nextId } = require('../data/store');
const { isValidEmail, validatePassword } = require('../utils/validators');

// Quita datos sensibles antes de responder
function toPublicUser(user) {
  return {
    id: user.id,
    email: user.email,
    fullName: user.fullName,
    store: user.store,
    role: user.role,
    createdAt: user.createdAt,
  };
}

async function register(req, res) {
  try {
    const { email, password, fullName, store } = req.body;

    // 1. Campos obligatorios
    if (!email || !password || !fullName || !store) {
      return res.status(400).json({
        ok: false,
        mensaje: 'Todos los campos son obligatorios: email, password, fullName, store',
      });
    }

    // 2. Formato de email
    if (!isValidEmail(email)) {
      return res.status(400).json({ ok: false, mensaje: 'El email no tiene un formato válido' });
    }

    // 3. Email único
    const normalizedEmail = email.trim().toLowerCase();
    if (users.some((u) => u.email === normalizedEmail)) {
      return res.status(409).json({ ok: false, mensaje: 'Ese email ya está registrado' });
    }

    // 4. Contraseña fuerte
    const passwordErrors = validatePassword(password);
    if (passwordErrors.length > 0) {
      return res.status(400).json({
        ok: false,
        mensaje: 'La contraseña no cumple los requisitos',
        errores: passwordErrors,
      });
    }

    // 5. Cifrar contraseña y guardar usuario
    const passwordHash = await bcrypt.hash(password, 10);

    const newUser = {
      id: nextId(),
      email: normalizedEmail,
      passwordHash,
      fullName: fullName.trim(),
      store: store.trim(),
      role: 'ventas', // el rol por defecto; nadie se registra como admin
      failedAttempts: 0, // se usará en la Etapa 3 (bloqueo)
      lockUntil: null, // se usará en la Etapa 3 (bloqueo)
      mfaEnabled: false, // se usará en la Etapa 4 (MFA)
      mfaSecret: null, // se usará en la Etapa 4 (MFA)
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

module.exports = { register, toPublicUser };