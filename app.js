const express = require('express');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const winston = require('winston');

const app = express();

// Middleware
app.use(express.json());
app.use(helmet());

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

// Dummy user storage (for lab only)
let users = [];

// REGISTER ROUTE
app.post('/register', async (req, res) => {
  logger.info('Register endpoint accessed');

  const { email, password } = req.body;

  // Validate email
  if (!validator.isEmail(email)) {
    return res.status(400).json({ message: 'Invalid email' });
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({ email, password: hashedPassword });

  res.json({
    message: 'User registered securely',
    hashedPassword: hashedPassword
  });
});

// LOGIN ROUTE
app.post('/login', async (req, res) => {
  logger.info('Login attempt made');

  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(400).json({ message: 'User not found' });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Wrong password' });
  }

  const token = jwt.sign({ email: user.email }, 'secret-key');

  res.json({
    message: 'Login successful',
    token: token
  });
});

// START SERVER
app.listen(3000, () => {
  logger.info('Application started');
  console.log('Server running on port 3000');
});