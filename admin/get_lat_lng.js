const express = require('express');
const mysql = require('mysql');
const path = require('path');

const app = express();

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// MySQL connection setup
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'YOUR-MYSQL-KEY',  // Replace with your MySQL password
  database: 'pwncrack'
});

connection.connect(err => {
  if (err) {
    console.error('Connection failed: ' + err.stack);
    return;
  }
  console.log('Connected as id ' + connection.threadId);
});

// Endpoint to fetch latitude, longitude, SSID, and password data
app.get('/locations', (req, res) => {
  const sql = `
    SELECT lat AS latitude, longitude, SSID, password
    FROM hash_data
    WHERE lat IS NOT NULL AND longitude IS NOT NULL
  `;
  connection.query(sql, (error, results) => {
    if (error) {
      console.error('Error executing query: ' + error.stack);
      res.status(500).json({ error: 'Database query failed' });
      return;
    }
    res.json(results);
  });
});


app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'map.html'));
});

// Start the server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
