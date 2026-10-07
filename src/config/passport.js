const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const { users, nextId } = require('../data/store');

// Busca al usuario por email; si no existe, lo crea (sin contraseña)
function findOrCreateSocialUser({ email, fullName, provider }) {
  let user = users.find((u) => u.email === email);
  if (!user) {
    user = {
      id: nextId(),
      email,
      passwordHash: null,
      fullName,
      store: 'Sin asignar',
      role: 'ventas',
      failedAttempts: 0,
      lockUntil: null,
      mfaEnabled: false,
      mfaSecret: null,
      mfaTempSecret: null,
      mfaSession: null,
      mfaFailedAttempts: 0,
      provider,
      createdAt: new Date().toISOString(),
    };
    users.push(user);
  }
  return user;
}

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}/api/auth/google/callback`,
    },
    (accessToken, refreshToken, profile, done) => {
      const email = profile.emails && profile.emails[0] && profile.emails[0].value;
      if (!email) return done(new Error('Google no entregó un email'));
      const user = findOrCreateSocialUser({
        email: email.toLowerCase(),
        fullName: profile.displayName,
        provider: 'google',
      });
      return done(null, user);
    }
  )
);

passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}/api/auth/github/callback`,
      scope: ['user:email'],
    },
    (accessToken, refreshToken, profile, done) => {
      // Si el email de GitHub es privado, usamos el correo noreply
      const email =
        (profile.emails && profile.emails[0] && profile.emails[0].value) ||
        `${profile.username}@users.noreply.github.com`;
      const user = findOrCreateSocialUser({
        email: email.toLowerCase(),
        fullName: profile.displayName || profile.username,
        provider: 'github',
      });
      return done(null, user);
    }
  )
);

module.exports = passport;