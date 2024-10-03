// db.js
const { Pool } = require('pg');

// Create a pool instance with your PostgreSQL configuration
const pool = new Pool({
    user: 'postgres',           // Replace with your PostgreSQL username
    host: 'localhost',          // Database host
    database: 'gateapp',       // Name of your database
    password: 'admin',          // Replace with your PostgreSQL password
    port: 5432,                 // Default PostgreSQL port
});

// Export the pool for use in other files
module.exports = pool;
