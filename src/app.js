const express = require('express');
const dotenv = require('dotenv');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const xss = require('xss-clean');
const bodyParser = require('body-parser');
const hpp = require('hpp');
const multer = require('multer');
const path = require('path');

const imageRoutes = require('./routes/image.route');
const userRoutes = require('./routes/user.route');

dotenv.config();

const app = express();
const port = process.env.PORT || 8000;
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
});

let users = [];

// Delete these lines once users can log properly
// Check if the 'default' user exists, and if not, create it
const defaultUser = { id: 1, username: 'default', email: 'default@exemple.com', password: 'default' };
if (!users.find(user => user.username === 'default')) {
    users.push(defaultUser);
}

// Set up storage for uploaded images
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'data/images/'); // Folder where images will be stored
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname); // Unique filename
    },
});

const upload = multer({ storage });

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

app.use('/images', express.static(path.join(__dirname, 'data/images')));

app.use('/images', imageRoutes);
app.use('/users', userRoutes);

app.get('/', (req, res) => {
    res.set('Content-Type', 'text/html');
    res.send(`
        <html>
        <head>
            <title>Upload Image</title>
        </head>
        <body>
            <h1>Upload an Image</h1>
            <form action="/images/upload" method="POST" enctype="multipart/form-data">
                <input type="file" name="image" accept="image/*" required />
                <button type="submit">Upload</button>
            </form>
        </body>
        </html>
    `);
});

app.listen(port, () => {
    console.log('Server app listening on port ' + port);
});