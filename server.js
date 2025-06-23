require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
const port = 3000;

// Archivos estáticos
app.use('/assets', express.static(path.join(__dirname, 'assets')));

// Servir archivos .html directamente
app.use(express.static(__dirname));

// Configuración de conexión PostgreSQL usando .env
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});



// Middleware para parsear application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));
// Middleware para parsear JSON en caso de que quieras usar JSON también
app.use(bodyParser.json());

// Rutas para servir archivos HTML desde la raíz
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

// Registro de usuario
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

// Login robusto sin JWT
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

    // Login exitoso: enviar nombre para localStorage
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

// Servir carpeta assets (CSS, JS, imágenes)
app.use('/assets', express.static(path.join(__dirname, 'assets')));

app.use(express.static(__dirname));


// Página 404 personalizada (debe ir al final de todas las rutas)
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, '404.html'));
  });
  

// Iniciar servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});


// Ruta para páginas no encontradas (404)
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, '404.html'));
  });
  