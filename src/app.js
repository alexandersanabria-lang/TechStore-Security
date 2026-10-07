const express = require('express');
const path = require('path');
const passport = require('./config/passport');
const authRoutes = require('./routes/auth.routes');

const app = express();

app.use(express.json());
app.use(passport.initialize());

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    mensaje: 'TechStore Security API funcionando'
  });
});

app.use('/api/auth', authRoutes);

module.exports = app;