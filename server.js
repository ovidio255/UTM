require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});

app.use(limiter);
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.use(express.static(__dirname));

app.get(['/', '/login.html', '/register.html', '/index.html', '/forgot-password.html', '/reset-password.html'], (req, res) => {
  const file = req.path === '/' ? 'login.html' : req.path;
  res.sendFile(path.join(__dirname, file));
});

app.post('/forms/contact.php', async (req, res) => {
  const { name, email, subject, message } = req.body;
  if (![name, email, subject, message].every(Boolean)) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
  }
  try {
    console.log('Mensaje recibido:', { name, email, subject, message });
    res.status(200).json({ message: 'Mensaje enviado correctamente.' });
  } catch (err) {
    console.error('Error al procesar el formulario:', err);
    res.status(500).json({ error: 'Error en el servidor al enviar el mensaje.' });
  }
});

app.post('/register', async (req, res) => {
  const { name, email, password, confirm_password } = req.body;
  if (![name, email, password, confirm_password].every(Boolean)) {
    return res.status(400).send('Todos los campos son obligatorios');
  }
  if (password !== confirm_password) {
    return res.status(400).send('Las contraseñas no coinciden');
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO usuarios (name, email, password) VALUES ($1, $2, $3)',
      [name.trim(), email.trim().toLowerCase(), hashedPassword]
    );
    res.status(201).send('Usuario registrado correctamente');
  } catch (error) {
    console.error('Error en /register:', error);
    res.status(500).send('Error al registrar usuario');
  }
});

app.post('/login', async (req, res) => {
  try {
    let { email, password } = req.body;
    if (![email, password].every(Boolean)) {
      return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
    }
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email.trim().toLowerCase()]);
    if (!result.rowCount) {
      return res.status(401).json({ error: 'Correo no encontrado o incorrecto' });
    }
    const user = result.rows[0];
    const isPasswordCorrect = await bcrypt.compare(password.trim(), user.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }
    res.status(200).json({ message: 'Login exitoso', redirect: '/index.html', name: user.name });
  } catch (error) {
    console.error('Error en /login:', error);
    res.status(500).json({ error: 'Error en el servidor. Intenta más tarde.' });
  }
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Correo requerido' });
  try {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000);
    await pool.query('INSERT INTO password_resets (email, token, expires_at) VALUES ($1, $2, $3)', [email.trim().toLowerCase(), token, expiresAt]);
    const resetUrl = `http://localhost:${port}/reset-password.html?token=${token}`;
    const mailOptions = {
      from: `"Soporte UTM" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Recuperación de contraseña',
      html: `<p>Haz clic en el siguiente enlace para recuperar tu contraseña:</p><a href="${resetUrl}">${resetUrl}</a><p>Este enlace expira en 1 hora.</p>`
    };
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Si el correo está registrado, se envió un email' });
  } catch (error) {
    console.error('Error enviando correo:', error);
    res.status(500).json({ error: 'Error enviando correo' });
  }
});

app.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (![token, password].every(Boolean)) {
    return res.status(400).json({ error: 'Token y contraseña son obligatorios' });
  }
  try {
    const result = await pool.query('SELECT email, expires_at FROM password_resets WHERE token = $1', [token]);
    if (!result.rowCount) {
      return res.status(400).json({ error: 'Token inválido' });
    }
    const { email, expires_at } = result.rows[0];
    if (new Date() > expires_at) {
      return res.status(400).json({ error: 'Token expirado' });
    }
    const hashedPassword = await bcrypt.hash(password.trim(), 10);
    await pool.query('UPDATE usuarios SET password = $1 WHERE email = $2', [hashedPassword, email]);
    await pool.query('DELETE FROM password_resets WHERE token = $1', [token]);
    res.status(200).json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error('Error en /reset-password:', error);
    res.status(500).json({ error: 'Error interno. Intenta más tarde.' });
  }
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});

app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
