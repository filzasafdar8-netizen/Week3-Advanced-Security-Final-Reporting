const express = require('express');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');

const app = express();
app.use(express.json());
app.use(helmet());

// Dummy database (for demo)
const users = [];

// Register route
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    if (!validator.isEmail(email)) return res.status(400).send('Invalid email');
    if (!password || password.length < 6) return res.status(400).send('Password too short');

    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({ email, password: hashedPassword });

    res.send({ message: 'User registered securely', hashedPassword });
});

// Login route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);

    if (!user) return res.status(400).send('User not found');

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).send('Wrong password');

    const token = jwt.sign({ email }, 'your-secret-key', { expiresIn: '1h' });

    res.send({ message: 'Login successful', token });
});

// Test route
app.get('/', (req, res) => {
    res.send('Server is running!');
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});