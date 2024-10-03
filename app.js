// app.js
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const app = express();
const pool = require('./db');  // Import the pool from db.js

// Middleware for parsing form data
app.use(express.urlencoded({ extended: true }));

// Session and flash messages setup
app.use(session({
    secret: 'your_secret_key', // Replace with your own secret
    resave: false,
    saveUninitialized: true
}));
app.use(flash());

// Make session and flash messages available in all templates
app.use((req, res, next) => {
    res.locals.session = req.session;
    res.locals.messages = req.flash();
    next();
});

// Static folder for serving CSS and images
app.use(express.static(path.join(__dirname, 'public')));

// Set the view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Helper function to hash passwords
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// Middleware to ensure the user is authenticated
function ensureAuthenticated(req, res, next) {
    if (req.session.user_id) {
        return next();
    }
    res.redirect('/login');
}

// Route for the home page
app.get('/', (req, res) => {
    res.render('layout', { 
        title: 'GateApp - Welcome', 
        session: req.session,
        view: 'index'  // Pass the name of the view to include
    });
});

// Route for displaying the registration page
app.get('/register', (req, res) => {
    res.render('layout', { 
        title: 'Register', 
        session: req.session,
        view: 'register'
    });
});

// Route for handling registration
app.post('/register', async (req, res) => {
    const { username, email, password, confirm_password, user_type } = req.body;

    if (password !== confirm_password) {
        req.flash('danger', 'Passwords do not match');
        return res.redirect('/register');
    }

    const passwordHash = hashPassword(password);

    try {
        const client = await pool.connect();
        let queryCheck, queryInsert;

        if (user_type === 'resident') {
            queryCheck = 'SELECT id FROM residents WHERE email = $1';
            queryInsert = 'INSERT INTO residents (username, email, password_hash) VALUES ($1, $2, $3)';
        } else if (user_type === 'security') {
            queryCheck = 'SELECT id FROM security_personnel WHERE email = $1';
            queryInsert = 'INSERT INTO security_personnel (name, email, password_hash) VALUES ($1, $2, $3)';
        } else {
            req.flash('danger', 'Invalid user type');
            return res.redirect('/register');
        }

        // Check if the email is already registered
        const result = await client.query(queryCheck, [email]);

        if (result.rows.length > 0) {
            req.flash('danger', 'Email is already registered');
            client.release();
            return res.redirect('/register');
        }

        // Insert the new user into the database
        await client.query(queryInsert, [username, email, passwordHash]);
        client.release();

        req.flash('success', 'Registration successful! Please log in.');
        res.redirect('/login');
    } catch (err) {
        console.error(err);
        req.flash('danger', 'Error during registration');
        res.redirect('/register');
    }
});

// Route for displaying the login page
app.get('/login', (req, res) => {
    res.render('layout', { 
        title: 'Login', 
        session: req.session,
        view: 'login'
    });
});

// Route for handling login
app.post('/login', async (req, res) => {
    const { email, password, user_type } = req.body;
    const passwordHash = hashPassword(password);

    try {
        const client = await pool.connect();
        let query;
        if (user_type === 'resident') {
            query = 'SELECT id, username FROM residents WHERE email = $1 AND password_hash = $2';
        } else if (user_type === 'security') {
            query = 'SELECT id, name FROM security_personnel WHERE email = $1 AND password_hash = $2';
        } else {
            req.flash('danger', 'Invalid user type');
            client.release();
            return res.redirect('/login');
        }

        const result = await client.query(query, [email, passwordHash]);
        client.release();

        if (result.rows.length > 0) {
            const user = result.rows[0];
            req.session.user_id = user.id;
            req.session.user_name = user.username || user.name;
            req.session.user_type = user_type;

            req.flash('success', `Welcome, ${req.session.user_name}!`);
            if (user_type === 'resident') {
                return res.redirect('/resident');
            } else {
                return res.redirect('/security');
            }
        } else {
            req.flash('danger', 'Invalid email or password');
            res.redirect('/login');
        }
    } catch (err) {
        console.error(err);
        req.flash('danger', 'Error during login');
        res.redirect('/login');
    }
});

// Route to log out
app.get('/logout', (req, res) => {
    req.session.destroy();
    req.flash('info', 'You have been logged out');
    res.redirect('/');
});

// Route for displaying the resident portal
app.get('/resident', ensureAuthenticated, (req, res) => {
    if (req.session.user_type !== 'resident') {
        return res.redirect('/login');
    }
    res.render('layout', { 
        title: 'Resident Portal', 
        session: req.session,
        view: 'resident'
    });
});

// Route for handling resident actions
app.post('/resident', ensureAuthenticated, async (req, res) => {
    if (req.session.user_type !== 'resident') {
        return res.redirect('/login');
    }

    const { guest_name } = req.body;
    const access_code = uuidv4().substring(0, 8);

    try {
        const client = await pool.connect();
        await client.query('INSERT INTO guests (resident_id, name, access_code) VALUES ($1, $2, $3)', 
            [req.session.user_id, guest_name, access_code]);
        client.release();

        req.flash('success', `Guest ${guest_name} added with access code ${access_code}`);
        res.redirect('/resident');
    } catch (err) {
        console.error(err);
        req.flash('danger', 'Error adding guest');
        res.redirect('/resident');
    }
});

// Route for displaying the security portal
app.get('/security', ensureAuthenticated, (req, res) => {
    if (req.session.user_type !== 'security') {
        return res.redirect('/login');
    }
    res.render('layout', { 
        title: 'Security Portal', 
        session: req.session,
        view: 'security'
    });
});

// Route for handling security actions
app.post('/security', ensureAuthenticated, async (req, res) => {
    if (req.session.user_type !== 'security') {
        return res.redirect('/login');
    }

    const { access_code } = req.body;

    try {
        const client = await pool.connect();
        const guestResult = await client.query('SELECT id, name FROM guests WHERE access_code = $1', [access_code]);

        if (guestResult.rows.length > 0) {
            const guest = guestResult.rows[0];
            await client.query('INSERT INTO access_logs (guest_id, security_personnel_id, access_granted) VALUES ($1, $2, $3)', 
                [guest.id, req.session.user_id, true]);
            req.flash('success', `Access granted for guest: ${guest.name}`);
        } else {
            req.flash('danger', 'Invalid access code');
        }
        client.release();
        res.redirect('/security');
    } catch (err) {
        console.error(err);
        req.flash('danger', 'Error during access check');
        res.redirect('/security');
    }
});

// Route to log out
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.render('layout', { 
        title: 'Logged Out', 
        session: req.session,
        view: 'logout'
    });
});

// Start the server
app.listen(3000, () => {
    console.log('Server running on port 3000');
});
