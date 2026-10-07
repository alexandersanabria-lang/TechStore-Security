const express = require('express');

const app = express();

app.use(express.json());

app.get('/api/health', (req, res) => {
  res.json({ ok: true, mensaje: 'TechStore Security API funcionando' });
});

module.exports = app;