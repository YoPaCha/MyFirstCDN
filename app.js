const express = require('express');
const dotenv = require('dotenv');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const xss = require('xss-clean');
const bodyParser = require('body-parser');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');

dotenv.config();

const app = express();
const port = process.env.PORT || 8000;
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
});

// Set security headers
app.use(helmet());

// Set CORS policy
app.use(cors({
    origin: 'https://localhost:8000',
    methods: ['GET', 'POST',],
}))

// Rate Limiting
app.use(limiter);

// Parse incoming request bodies in order to prevent DoS attacks
app.use(bodyParser.json({ limit: '10kb' })); // adjust limit as needed

// Prevent cross-site scripting (XSS) attacks
app.use(xss());

// Sanitize query input for MongoDB, preventing NoSQL injection attacks
app.use(mongoSanitize());

// Filter duplicate query parameters, prventing HTTP parameter pollution
app.use(hpp());

// Session Management
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: true,
        httpOnly: true, // restrict access from JavaScript
    }
}));

app.get('/', (req, res) => {
    res.set('Content-Type', 'text/html');
    res.send('Hello world !!');
});

app.listen(port, () => {
    console.log('Server app listening on port ' + port);
});