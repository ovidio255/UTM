require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;

// PostgreSQL
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

app.get('/index.html', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.redirect('/login.html');
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});


// Sesiones
app.use(session({
  secret: 'clave_segura_y_unica', // 🔐 cambia esto en producción
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // usar true si estás en HTTPS
}));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Rutas HTML
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/index.html', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login.html');
  }
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

// Registro
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

    // Guardar sesión
    req.session.user = { name: user.name, email: user.email };

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

// Página 404 personalizada
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`✅ Servidor corriendo en http://localhost:${port}`);
});
