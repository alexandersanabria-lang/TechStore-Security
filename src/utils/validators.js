const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function isValidEmail(email) {
  return typeof email === 'string' && EMAIL_REGEX.test(email);
}

// Devuelve una lista con los requisitos que NO se cumplen
function validatePassword(password) {
  const errors = [];

  if (typeof password !== 'string' || password.length < 8) {
    errors.push('Debe tener mínimo 8 caracteres');
  }
  if (typeof password !== 'string' || !/[A-Z]/.test(password)) {
    errors.push('Debe incluir al menos una mayúscula');
  }
  if (typeof password !== 'string' || !/[0-9]/.test(password)) {
    errors.push('Debe incluir al menos un número');
  }
  if (typeof password !== 'string' || !/[^A-Za-z0-9]/.test(password)) {
    errors.push('Debe incluir al menos un carácter especial');
  }

  return errors;
}

module.exports = { isValidEmail, validatePassword };