require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;

// PostgreSQL - Configuración mejorada
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  timezone: 'UTC'
});

// Configuración mejorada del transportador de correo
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  },
  tls: {
    rejectUnauthorized: false
  },
  pool: true,
  maxConnections: 5,
  maxMessages: 100
});

// Middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'clave_segura_y_unica',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Rutas HTML
app.get('/', (req, res) => res.redirect('/login.html'));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/forgot-password.html', (req, res) => res.sendFile(path.join(__dirname, 'forgot-password.html')));
app.get('/index.html', (req, res) => {
  if (!req.session?.user) return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
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
    res.status(500).send(error.code === '23505' ? 'El correo ya está registrado' : 'Error al registrar usuario');
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    let { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
    
    email = email.trim();
    password = password.trim();

    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Correo no encontrado o incorrecto' });

    const user = result.rows[0];
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) return res.status(401).json({ error: 'Contraseña incorrecta' });

    req.session.user = { name: user.name, email: user.email };
    res.status(200).json({ message: 'Login exitoso', redirect: '/index.html', name: user.name });
  } catch (error) {
    console.error('Error en /login:', error);
    res.status(500).json({ error: 'Error en el servidor. Intenta más tarde.' });
  }
});

// Ruta para solicitar restablecimiento de contraseña (Corregida)
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'El correo es obligatorio' });

  try {
    // Verificar si el usuario existe
    const userResult = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email.trim()]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'No existe una cuenta con este correo electrónico' });
    }

    // Generar token de 4 dígitos
    const token = Math.floor(1000 + Math.random() * 9000).toString();
    const expires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos

    console.log(`[DEBUG] Token generado para ${email}: ${token}, expira: ${expires}`);

    // Guardar el token en la base de datos
    await pool.query(
      `INSERT INTO password_resets (email, token, expires) 
       VALUES ($1, $2, $3) 
       ON CONFLICT (email) 
       DO UPDATE SET token = $2, expires = $3, created_at = NOW()`,
      [email.trim(), token, expires]
    );

    // Configurar y enviar el correo
    const mailOptions = {
      from: `"Soporte UTM" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Código para restablecer tu contraseña',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background-color: #06415D; color: white; padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1>Restablecer Contraseña</h1>
          </div>
          <div style="background-color: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd;">
            <p style="font-size: 16px; color: #333;">Hola,</p>
            <p style="font-size: 16px; color: #333; line-height: 1.5;">
              Has solicitado restablecer tu contraseña. Usa el siguiente código de 4 dígitos:
            </p>
            <div style="background-color: #fff; border: 2px solid #06415D; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
              <h2 style="color: #06415D; font-size: 32px; letter-spacing: 8px; margin: 0;">${token}</h2>
            </div>
            <p style="font-size: 14px; color: #666; margin-top: 20px;">
              Este código expirará en 15 minutos por seguridad.
            </p>
            <p style="font-size: 14px; color: #666;">
              Si no solicitaste este cambio, puedes ignorar este correo.
            </p>
          </div>
        </div>
      `
    };

    // Enviar correo con manejo de errores mejorado
    const info = await transporter.sendMail(mailOptions);
    console.log(`Correo enviado a ${email}:`, info.messageId);
    res.status(200).json({ message: 'Código enviado correctamente' });

  } catch (error) {
    console.error('Error detallado en /forgot-password:', {
      message: error.message,
      code: error.code,
      stack: error.stack,
      response: error.response
    });
    
    let errorMessage = 'Error al enviar el código. Intenta más tarde.';
    
    if (error.code === 'EAUTH') {
      errorMessage = 'Error de autenticación con el servicio de correo. Verifica tus credenciales.';
    } else if (error.code === 'ECONNECTION') {
      errorMessage = 'No se pudo conectar al servidor de correo. Verifica tu conexión a internet.';
    } else if (error.responseCode === 535) {
      errorMessage = 'Error de autenticación. Verifica tu usuario y contraseña de correo.';
    }
    
    res.status(500).json({ error: errorMessage });
  }
});

// Ruta para verificar el token (Corregida)

// Ruta para verificar el token (Versión corregida)
app.post('/verify-reset-token', async (req, res) => {
  const { email, token } = req.body;
  if (!email || !token || token.length !== 4) {
    return res.status(400).json({ error: 'Se requiere un código de 4 dígitos válido' });
  }

  try {
    console.log(`[DEBUG] Verificando token para ${email}: ${token} a las ${new Date()}`);

    // Consulta mejorada que considera el tipo de dato
    const result = await pool.query(
      `SELECT * FROM password_resets 
       WHERE email = $1 
       AND token = $2 
       AND expires > NOW()`,
      [email.trim(), token.trim()]
    );

    console.log(`[DEBUG] Resultados de verificación:`, {
      rows: result.rows,
      rowCount: result.rowCount,
      tokenType: typeof result.rows[0]?.token,
      inputTokenType: typeof token
    });

    if (result.rows.length === 0) {
      // Diagnóstico avanzado
      const dbRecord = await pool.query(
        'SELECT token, expires FROM password_resets WHERE email = $1',
        [email.trim()]
      );

      if (dbRecord.rows.length > 0) {
        const dbToken = dbRecord.rows[0].token;
        const isExpired = new Date() > new Date(dbRecord.rows[0].expires);
        
        console.log(`[DEBUG] Comparación detallada:`, {
          dbToken,
          inputToken: token,
          match: dbToken === token,
          dbTokenType: typeof dbToken,
          inputTokenType: typeof token,
          isExpired
        });

        return res.status(401).json({ 
          error: isExpired ? 'El código ha expirado. Solicita uno nuevo.' 
                          : 'Código incorrecto. Por favor verifica.' 
        });
      }

      return res.status(401).json({ error: 'No se encontró solicitud para este correo.' });
    }

    res.status(200).json({ message: 'Código verificado correctamente' });
  } catch (error) {
    console.error('Error en /verify-reset-token:', {
      message: error.message,
      stack: error.stack,
      query: error.query,
      parameters: error.parameters
    });
    res.status(500).json({ error: 'Error en el servidor. Intenta más tarde.' });
  }
});
// Ruta de prueba para correos
app.get('/test-email', async (req, res) => {
  try {
    const mailOptions = {
      from: `"Prueba UTM" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER,
      subject: 'Prueba de correo electrónico',
      text: 'Este es un correo de prueba del sistema de recuperación de contraseña',
      html: '<p>Este es un <b>correo de prueba</b> del sistema</p>'
    };
    
    const info = await transporter.sendMail(mailOptions);
    console.log('Mensaje enviado: %s', info.messageId);
    res.send('Correo de prueba enviado correctamente');
  } catch (error) {
    console.error('Error en prueba de correo:', {
      message: error.message,
      code: error.code,
      stack: error.stack
    });
    res.status(500).send(`Error al enviar correo de prueba: ${error.message}`);
  }
});

// Limpieza periódica de tokens expirados
setInterval(async () => {
  try {
    const { rowCount } = await pool.query('DELETE FROM password_resets WHERE expires < NOW()');
    if (rowCount > 0) console.log(`[CLEANUP] Eliminados ${rowCount} tokens expirados`);
  } catch (error) {
    console.error('Error en limpieza de tokens:', error);
  }
}, 3600000); // Cada hora

// Página 404 personalizada
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`✅ Servidor corriendo en http://localhost:${port}`);
});