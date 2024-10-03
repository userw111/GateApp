// routes/index.js
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const pool = require('../db'); // Adjust this path according to your database setup
const crypto = require('crypto');

// Hash password
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

// Home route
router.get('/', (req, res) => {
    res.render('index', { title: 'GateApp - Welcome' });
});

// Login form display
router.get('/login', (req, res) => {
    res.render('login', { title: 'Login' });
});

// Login route
router.post('/login', async (req, res) => {
    const { email, password, user_type } = req.body;
    const passwordHash = hashPassword(password);

    try {
        const client = await pool.connect();
        let query;
        if (user_type === 'resident') {
            query = 'SELECT id, username FROM residents WHERE email = $1 AND password_hash = $2';
        } else {
            query = 'SELECT id, name FROM security_personnel WHERE email = $1 AND password_hash = $2';
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

// Logout route
router.get('/logout', (req, res) => {
    req.session.destroy();
    req.flash('info', 'You have been logged out');
    res.redirect('/');
});

// Resident portal display
router.get('/resident', ensureAuthenticated, (req, res) => {
    if (req.session.user_type !== 'resident') {
        return res.redirect('/login');
    }
    res.render('resident', { title: 'Resident Portal' });
});

// Resident portal action
router.post('/resident', ensureAuthenticated, async (req, res) => {
    if (req.session.user_type !== 'resident') {
        return res.redirect('/login');
    }

    const { guest_name } = req.body;
    const access_code = uuidv4().substring(0, 8);

    try {
        const client = await pool.connect();
        await client.query(
            'INSERT INTO guests (resident_id, name, access_code) VALUES ($1, $2, $3)', 
            [req.session.user_id, guest_name, access_code]
        );
        client.release();

        req.flash('success', `Guest ${guest_name} added with access code ${access_code}`);
        res.redirect('/resident');
    } catch (err) {
        console.error(err);
        req.flash('danger', 'Error adding guest');
        res.redirect('/resident');
    }
});

// Security portal display
router.get('/security', ensureAuthenticated, (req, res) => {
    if (req.session.user_type !== 'security') {
        return res.redirect('/login');
    }
    res.render('security', { title: 'Security Portal' });
});

// Security portal action
router.post('/security', ensureAuthenticated, async (req, res) => {
    if (req.session.user_type !== 'security') {
        return res.redirect('/login');
    }

    const { access_code } = req.body;

    try {
        const client = await pool.connect();
        const guestResult = await client.query(
            'SELECT id, name FROM guests WHERE access_code = $1', 
            [access_code]
        );

        if (guestResult.rows.length > 0) {
            const guest = guestResult.rows[0];
            await client.query(
                'INSERT INTO access_logs (guest_id, security_personnel_id, access_granted) VALUES ($1, $2, $3)', 
                [guest.id, req.session.user_id, true]
            );
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

module.exports = router;
