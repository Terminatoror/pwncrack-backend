const mysql = require('mysql');
const axios = require('axios');

// Configuration
const WIGLE_API_KEY = 'YOUR-WIGLE-KEY';  // Replace with your Wigle API key
const MAX_REQUESTS = 100;  // Maximum number of requests to send

// Initialize MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'YOUR-MYSQL-PASSWORD',  // Replace with your MySQL password
  database: 'pwncrack'
});

db.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    process.exit(1);
  }
  console.log('Connected to MySQL');
  updateLatLong();
});

async function updateLatLong() {
  try {
    // Fetch hashes with passwords and without lat/long values
    let rows = await query(`SELECT \`key\`, BSSID FROM hash_data WHERE password IS NOT NULL AND (lat IS NULL OR longitude IS NULL) LIMIT ${MAX_REQUESTS}`);
    
    if (rows.length < MAX_REQUESTS) {
      // If not enough hashes with passwords, fetch additional hashes without passwords
      const remaining = MAX_REQUESTS - rows.length;
      const additionalRows = await query(`SELECT \`key\`, BSSID FROM hash_data WHERE password IS NULL AND (lat IS NULL OR longitude IS NULL) LIMIT ${remaining}`);
      rows = rows.concat(additionalRows);
    }

    for (const row of rows) {
      const { key, BSSID } = row;
      const response = await fetchWigleData(BSSID);
      if (response) {
        const { lat, lon } = response;
        await query(`UPDATE hash_data SET lat = ?, longitude = ? WHERE \`key\` = ? AND BSSID = ?`, [lat, lon, key, BSSID]);
        console.log(`Updated lat/long for BSSID: ${BSSID}, lat: ${lat}, lon: ${lon}`);
      }
      await delay(1000);  // Add delay of 1 second between requests
    }
  } catch (err) {
    console.error('Error updating lat/long:', err);
  } finally {
    db.end();
  }
}

function query(sql, params) {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, results) => {
      if (err) return reject(err);
      resolve(results);
    });
  });
}

async function fetchWigleData(bssid) {
  try {
    const response = await axios.get('https://api.wigle.net/api/v2/network/detail', {
      headers: {
        'Authorization': "Basic YOUR-WIGLE-KEY"  // Replace with your Wigle API key
      },
      params: {
        netid: bssid
      }
    });
    if (response.data && response.data.results && response.data.results.length > 0) {
      const { trilat: lat, trilong: lon } = response.data.results[0];
      return { lat, lon };
    }
  } catch (err) {
    console.error(`Error fetching data for BSSID: ${bssid}`, err);
  }
  return null;
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
