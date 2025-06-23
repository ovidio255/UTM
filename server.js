require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const port = process.env.PORT || 3000;

// Configuración PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// Configura Nodemailer para enviar correos (Gmail ejemplo)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Servir archivos estáticos y HTML
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.use(express.static(__dirname));

// Rutas HTML principales
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});
app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});
app.get('/index.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/forgot-password.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'forgot-password.html'));
});
app.get('/reset-password.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'reset-password.html'));
});

// Registro usuario
app.post('/register', async (req, res) => {
  const { name, email, password, confirm_password } = req.body;

  if (!name || !email || !password || !confirm_password) {
    return res.status(400).send('Todos los campos son obligatorios');
  }
  if (password !== confirm_password) {
    return res.status(400).send('Las contraseñas no coinciden');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO usuarios (name, email, password) VALUES ($1, $2, $3)',
      [name.trim(), email.trim(), hashedPassword]
    );
    res.status(201).send('Usuario registrado correctamente');
  } catch (error) {
    console.error('Error en /register:', error);
    res.status(500).send('Error al registrar usuario');
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    let { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
    }
    email = email.trim();
    password = password.trim();

    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Correo no encontrado o incorrecto' });
    }
    const user = result.rows[0];
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }

    res.status(200).json({
      message: 'Login exitoso',
      redirect: '/index.html',
      name: user.name,
    });
  } catch (error) {
    console.error('Error en /login:', error);
    res.status(500).json({ error: 'Error en el servidor. Intenta más tarde.' });
  }
});

// Recuperación de contraseña - enviar email con token
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'El correo es obligatorio' });

  try {
    const userCheck = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (userCheck.rowCount === 0) {
      // Respuesta genérica para no revelar info
      return res.status(200).json({ message: 'Si el correo está registrado, se envió un email para recuperar la contraseña.' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000); // 1 hora validez

    // Guarda o actualiza token en tabla password_resets
    await pool.query(
      `INSERT INTO password_resets (email, token, expires_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (email) DO UPDATE SET token = EXCLUDED.token, expires_at = EXCLUDED.expires_at`,
      [email, token, expiresAt]
    );

    const resetUrl = `https://utm-af9b.onrender.com/reset-password.html?token=${token}`;

    const mailOptions = {
      from: `"Tu Empresa" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Recupera tu contraseña',
      html: `
        <p>Haz click en el siguiente enlace para recuperar tu contraseña:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>El enlace es válido por 1 hora.</p>
      `
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: 'Si el correo está registrado, se envió un email para recuperar la contraseña.' });
  } catch (error) {
    console.error('Error en /forgot-password:', error);
    res.status(500).json({ error: 'Error interno. Intenta más tarde.' });
  }
});

// Restablecer contraseña con token
app.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token y contraseña son obligatorios' });

  try {
    const result = await pool.query('SELECT email, expires_at FROM password_resets WHERE token = $1', [token]);
    if (result.rowCount === 0) return res.status(400).json({ error: 'Token inválido o expirado' });

    const { email, expires_at } = result.rows[0];
    if (new Date() > expires_at) return res.status(400).json({ error: 'Token expirado' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('UPDATE usuarios SET password = $1 WHERE email = $2', [hashedPassword, email]);

    await pool.query('DELETE FROM password_resets WHERE token = $1', [token]);

    res.status(200).json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error('Error en /reset-password:', error);
    res.status(500).json({ error: 'Error interno. Intenta más tarde.' });
  }
});

// Página 404 personalizada (debe ir al final)
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
