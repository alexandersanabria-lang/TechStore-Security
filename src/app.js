const express = require('express');
const passport = require('./config/passport');
const authRoutes = require('./routes/auth.routes');

const app = express();

app.use(express.json());
app.use(passport.initialize());

app.get('/api/health', (req, res) => {
  res.json({ ok: true, mensaje: 'TechStore Security API funcionando' });
});

app.use('/api/auth', authRoutes);

module.exports = app;