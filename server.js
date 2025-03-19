const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const uuid = require('uuid');
const bodyParser = require('body-parser');
const session = require('express-session');
const { exec } = require('child_process');
const { extractHashesFromHC22000 } = require('./utils/hashProcessing');
const mysql = require('mysql');  // Replace sqlite3 with mysql
const os = require('os');
const nodemailer = require('nodemailer');  // Add this import
const favicon = require('serve-favicon');  // Add this import
const fetch = require('node-fetch');  // Add this import

const app = express();
const PORT = 80;
// Configurations
const HANDSHAKES_DIR = path.join(__dirname, 'handshakes');
const PROCESSED_DIR = path.join(__dirname, 'processed');
const RESULTS_DIR = path.join(__dirname, 'results');
const potfilePath = path.join(RESULTS_DIR, 'hashcat.potfile');
const BOSS_DIR = path.join(__dirname, 'boss');
const bossPotfilePath = path.join(BOSS_DIR, 'boss.potfile');
const WORDLISTS_DIR = path.join(__dirname, 'wordlists');

// Ensure directories exist
[HANDSHAKES_DIR, PROCESSED_DIR, RESULTS_DIR, BOSS_DIR, NOT_FOUND_DIR, WORDLISTS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
});

// In-memory work tracking (not working atm, commented out till its fixed)
// const assignedFiles = new Set(); // Remove this line

app.use(express.json());
app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));  // Add this middleware
app.use(express.static('public'));  // Ensure this is after the favicon middleware

// Serve static files from the /admin directory
app.use('/admin', express.static(path.join(__dirname, 'admin')));

// Initialize MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'MYSQL_PASSWORD_PLACEHOLDER',  // replaced API key with placeholder
  database: 'pwncrack'
});

db.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    process.exit(1);
  }
  console.log('Connected to MySQL');

  // Create tables if they don't exist
  db.query(`CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) PRIMARY KEY,
    \`key\` VARCHAR(255),
    theme VARCHAR(255) DEFAULT NULL,
    display VARCHAR(255) DEFAULT NULL,
    username VARCHAR(255) DEFAULT NULL,
    leaderboard VARCHAR(255) DEFAULT NULL,
    \`rank\` VARCHAR(255) DEFAULT NULL, 
    rank_time INT DEFAULT 0, 
    rank_activation DATETIME DEFAULT NULL
  )`);

  db.query(`CREATE TABLE IF NOT EXISTS upload_logs (
    email VARCHAR(255),
    file_name VARCHAR(255),
    timestamp DATETIME
  )`);

  db.query(`CREATE TABLE IF NOT EXISTS hash_data (
    \`key\` VARCHAR(255),
    hash VARCHAR(255),
    file_name VARCHAR(255),
    counter INT DEFAULT 0,
    last_assigned TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    password VARCHAR(255),
    SSID VARCHAR(255),
    BSSID VARCHAR(255),
    lat DECIMAL(10, 8),
    longitude DECIMAL(11, 8)
  )`);

  db.query(`CREATE TABLE IF NOT EXISTS hash_rate (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_key VARCHAR(255),
    cracker_id VARCHAR(255),
    file_name VARCHAR(255),
    hashrate BIGINT,
    processed_hashes BIGINT DEFAULT 0,
    session_time INT DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX user_key_idx (user_key)
  )`);

  db.query(`CREATE TABLE IF NOT EXISTS sent_rank_keys (
    email VARCHAR(255),
    rank_key VARCHAR(255),
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  // Ensure the hash_data table has the necessary columns
  db.query(`SHOW COLUMNS FROM hash_data`, (err, columns) => {
    if (err) {
      console.error("Error fetching table info:", err);
      return;
    }

    const columnNames = columns.map(col => col.Field);
    if (!columnNames.includes('counter')) {
      db.query(`ALTER TABLE hash_data ADD COLUMN counter INT DEFAULT 0`, (err) => {
        if (err) {
          console.error("Error adding counter column:", err);
        }
      });
    }
    if (!columnNames.includes('last_assigned')) {
      db.query(`ALTER TABLE hash_data ADD COLUMN last_assigned TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP`, (err) => {
        if (err) {
          console.error("Error adding last_assigned column:", err);
        } else {
          db.query(`UPDATE hash_data SET last_assigned = CURRENT_TIMESTAMP`, (err) => {
            if (err) {
              console.error("Error updating last_assigned column:", err);
            }
          });
        }
      });
    }
    if (!columnNames.includes('password')) {
      db.query(`ALTER TABLE hash_data ADD COLUMN password VARCHAR(255)`, (err) => {
        if (err) {
          console.error("Error adding password column:", err);
        }
      });
    }
    if (!columnNames.includes('SSID')) {
      db.query(`ALTER TABLE hash_data ADD COLUMN SSID VARCHAR(255)`, (err) => {
        if (err) {
          console.error("Error adding SSID column:", err);
        }
      });
    }
    if (!columnNames.includes('BSSID')) {
      db.query(`ALTER TABLE hash_data ADD COLUMN BSSID VARCHAR(255)`, (err) => {
        if (err) {
          console.error("Error adding BSSID column:", err);
        }
      });
    }
    if (!columnNames.includes('lat')) {
      db.query(`ALTER TABLE hash_data ADD COLUMN lat DECIMAL(10, 8)`, (err) => {
        if (err) {
          console.error("Error adding lat column:", err);
        }
      });
    }
    if (!columnNames.includes('longitude')) {
      db.query(`ALTER TABLE hash_data ADD COLUMN longitude DECIMAL(11, 8)`, (err) => {
        if (err) {
          console.error("Error adding longitude column:", err);
        }
      });
    }
  });

  // Ensure the users table has the necessary columns
  db.query(`SHOW COLUMNS FROM users`, (err, columns) => {
    if (err) {
      console.error("Error fetching table info:", err);
      return;
    }

    const columnNames = columns.map(col => col.Field);
    if (!columnNames.includes('theme')) {
      db.query(`ALTER TABLE users ADD COLUMN theme VARCHAR(255) DEFAULT NULL`, (err) => {
        if (err) {
          console.error("Error adding theme column:", err);
        }
      });
    }
    if (!columnNames.includes('display')) {
      db.query(`ALTER TABLE users ADD COLUMN display VARCHAR(255) DEFAULT NULL`, (err) => {
        if (err) {
          console.error("Error adding display column:", err);
        }
      });
    }
    if (!columnNames.includes('username')) {
      db.query(`ALTER TABLE users ADD COLUMN username VARCHAR(255) DEFAULT NULL`, (err) => {
        if (err) {
          console.error("Error adding username column:", err);
        }
      });
    }
    if (!columnNames.includes('leaderboard')) {
      db.query(`ALTER TABLE users ADD COLUMN leaderboard VARCHAR(255) DEFAULT NULL`, (err) => {
        if (err) {
          console.error("Error adding leaderboard column:", err);
        }
      });
    }
    if (!columnNames.includes('BSSID_display')) {
      db.query(`ALTER TABLE users ADD COLUMN \`BSSID_display\` VARCHAR(255) DEFAULT 'false'`, (err) => {
        if (err) {
          console.error("Error adding BSSID_display column:", err);
        }
      });
    }
    if (!columnNames.includes('rank')) {
      db.query(`ALTER TABLE users ADD COLUMN \`rank\` VARCHAR(255) DEFAULT NULL`, err => { if(err) console.error(err); });
    }
    if (!columnNames.includes('rank_time')) {
      db.query(`ALTER TABLE users ADD COLUMN rank_time INT DEFAULT 0`, err => { if(err) console.error(err); });
    }
    if (!columnNames.includes('rank_activation')) {
      db.query(`ALTER TABLE users ADD COLUMN rank_activation DATETIME DEFAULT NULL`, err => { if(err) console.error(err); });
    }
    if (!columnNames.includes('discord_webhook_url')) {
      db.query(`ALTER TABLE users ADD COLUMN discord_webhook_url VARCHAR(255) DEFAULT NULL`, (err) => {
        if (err) {
          console.error("Error adding discord_webhook_url column:", err);
        }
      });
    }
    if (!columnNames.includes('display_cracked_content')) {
      db.query(`ALTER TABLE users ADD COLUMN display_cracked_content VARCHAR(255) DEFAULT 'false'`, (err) => {
        if (err) {
          console.error("Error adding display_cracked_content column:", err);
        }
      });
    }
  });

  // Start the server after ensuring tables are created
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});

// Function to convert hex to ASCII
function hexToAscii(hex) {
  let str = '';
  for (let i = 0; i < hex.length; i += 2) {
    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return str;
}

// Function to update SSID and BSSID in the database
function updateSSIDAndBSSIDForHash(key, hash) {
  db.query(`SELECT SSID, BSSID FROM hash_data WHERE \`key\` = ? AND hash = ?`, [key, hash], (err, rows) => {
    if (err) {
      console.error("Error checking SSID and BSSID:", err);
      return;
    }
    if (!rows.length || !rows[0].SSID || !rows[0].BSSID) {
      const hashParts = hash.split('*');
      if (hashParts.length > 4) {
        const hexSSID = hashParts[5];
        const ssid = hexToAscii(hexSSID);
        let bssid = hashParts[3];  // Extract BSSID from the hash
        // Format BSSID to be valid
        bssid = bssid.match(/.{1,2}/g).join(':');
        db.query(`UPDATE hash_data SET SSID = ?, BSSID = ? WHERE \`key\` = ? AND hash = ?`, [ssid, bssid, key, hash], (err) => {
          if (err) {
            console.error("Error updating SSID and BSSID:", err);
          } else {
            console.log(`Updated SSID and BSSID for hash: ${hash}, SSID: ${ssid}, BSSID: ${bssid}`);
          }
        });
      }
    }
  });
}

const generateRandomString = (length) => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
};

const testPasswordWithHashcat = (hash, password, callback) => {
  const randomString = generateRandomString(6);

  // Create a temporary file to store the hash
  const tempHashFile = path.join(os.tmpdir(), `${randomString}_temp_hash.hc22000`);
  fs.writeFileSync(tempHashFile, hash);

  // Create a temporary file to store the password
  const tempWordlistFile = path.join(os.tmpdir(), `${randomString}_temp_wordlist.txt`);
  fs.writeFileSync(tempWordlistFile, password);

  // Hashcat command to test the password
  const hashcatCommand = `hashcat -m 22000 --quiet --potfile-disable -a 0 ${tempHashFile} ${tempWordlistFile}`;
  exec(hashcatCommand, (error, stdout, stderr) => {
    // Clean up temporary files
    fs.unlinkSync(tempHashFile);
    fs.unlinkSync(tempWordlistFile);

    if (error) {
      console.error(`Error running hashcat: ${stderr}`);
      callback(false);
    } else {
      callback(stdout.includes(password));
    }
  });
};

app.get('/results', (req, res) => {
  const userKey = req.query.key; // Get the key from the query parameters
  if (!userKey) {
    return res.status(400).json({ error: 'Bad Request: No key provided.' });
  }

  findKeyInDB(userKey, (keyData) => {
    if (!keyData) {
      return res.status(400).json({ error: 'Invalid session key.' });
    }

    db.query(`SELECT SSID, password, BSSID FROM hash_data WHERE \`key\` = ? AND password IS NOT NULL`, [userKey], (err, rows) => {
      if (err) {
        console.error("Error fetching cracked passwords:", err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!rows.length) {
        return res.json({ message: "No handshakes cracked yet." });
      }

      res.json(rows);
    });
  });
});

app.get('/check_potfile', (req, res) => {
    const userKey = req.query.key;
    if (!userKey) {
        return res.status(400).json({ error: 'Bad Request: No key provided.' });
    }

    findKeyInDB(userKey, (keyData) => {
        if (!keyData) {
            return res.status(400).json({ error: 'Invalid session key.' });
        }

        const userEmail = keyData.email;
        const userPotfilePath = path.join(RESULTS_DIR, `${userEmail}.potfile`);

        if (fs.existsSync(userPotfilePath)) {
            return res.json({ exists: true });
        } else {
            return res.json({ exists: false });
        }
    });
});

app.get('/download_potfile', (req, res) => {
    const userKey = req.query.key;
    if (!userKey) {
        return res.status(400).json({ error: 'Bad Request: No key provided.' });
    }

    findKeyInDB(userKey, (keyData) => {
        if (!keyData) {
            return res.status(400).json({ error: 'Invalid session key.' });
        }

        const userEmail = keyData.email;
        const userPotfilePath = path.join(RESULTS_DIR, `${userEmail}.potfile`);

        if (fs.existsSync(userPotfilePath)) {
            fs.readFile(userPotfilePath, 'utf-8', (err, data) => {
                if (err) {
                    return res.status(500).json({ error: 'Error reading the potfile.' });
                }

                const uniqueLines = new Set(data.split('\n'));
                const uniqueData = Array.from(uniqueLines).join('\n');

                const tempFilePath = path.join(RESULTS_DIR, `${userEmail}_unique.potfile`);
                fs.writeFile(tempFilePath, uniqueData, (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Error writing the unique potfile.' });
                    }
                    res.download(tempFilePath, `${userEmail}.potfile`, (err) => {
                        if (err) {
                            console.error('Error downloading the file:', err);
                        }
                        fs.unlink(tempFilePath, (err) => {
                            if (err) {
                                console.error('Error deleting the temporary file:', err);
                            }
                        });
                    });
                });
            });
        } else {
            res.status(404).json({ error: 'Potfile not found.' });
        }
    });
});

// Endpoint to download potfile for scripts and plugins
app.get('/download_potfile_script', (req, res) => {
    const userKey = req.query.key;
    if (!userKey) {
        return res.status(400).json({ error: 'Bad Request: No key provided.' });
    }

    findKeyInDB(userKey, (keyData) => {
        if (!keyData) {
            return res.status(400).json({ error: 'Invalid session key.' });
        }

        const userEmail = keyData.email;
        const userPotfilePath = path.join(RESULTS_DIR, `${userEmail}.potfile`);

        console.log(`Looking for potfile at: ${userPotfilePath}`); // Debugging information

        if (fs.existsSync(userPotfilePath)) {
            fs.readFile(userPotfilePath, 'utf-8', (err, data) => {
                if (err) {
                    return res.status(500).json({ error: 'Error reading the potfile.' });
                }

                const uniqueLines = new Set(data.split('\n'));
                const uniqueData = Array.from(uniqueLines).join('\n');

                res.setHeader('Content-Type', 'text/plain');
                res.send(uniqueData);
            });
        } else {
            console.log(`Potfile not found at: ${userPotfilePath}`); // Debugging information
            res.status(404).json({ error: 'Potfile not found.' });
        }
    });
});

// Function to get a random file with the lowest count and no password from HANDSHAKES_DIR
function getFileWithLowestCount(callback) {
  console.log("Fetching files with lowest count...");
  db.query(`SELECT file_name, counter FROM hash_data WHERE password IS NULL AND file_name LIKE '%.hc22000' ORDER BY counter ASC LIMIT 1`, (err, rows) => {
    if (err) {
      console.error("Error fetching files with lowest count:", err);
      callback(null);
    } else {
      console.log("Fetched rows:", rows);
      if (rows.length === 0) {
        console.log("No files without passwords found.");
        callback(null);
      } else {
        const file = rows[0].file_name;
        console.log("File with lowest count:", file);
        const filePath = path.join(HANDSHAKES_DIR, file);
        if (fs.existsSync(filePath)) {
          callback(file);
        } else {
          console.log("File does not exist in HANDSHAKES_DIR:", file);
          // Increment counter to skip this file then search for another
          db.query(`UPDATE hash_data SET counter = counter + 1000 WHERE file_name = ?`, [file], (err) => {
            if (err) {
              console.error("Error updating counter for missing file:", err);
            }
            getFileWithLowestCount(callback);
          });
        }
      }
    }
  });
}

// Get work endpoint
app.get('/get_work', (req, res) => {
  getFileWithLowestCount((file) => {
    if (!file) {
      return res.status(404).json({ error: 'No work available' });
    }

    // Update counter and last_assigned timestamp
    db.query(`UPDATE hash_data SET counter = counter + 1, last_assigned = CURRENT_TIMESTAMP WHERE file_name = ?`, [file], (err) => {
      if (err) {
        console.error("Error updating counter:", err);
      }
    });

    res.json({ 
      file_name: file,
      download_url: `http://${req.headers.host}/download/${file}`
    });
  });
});

// Download endpoint
app.get('/download/:file', (req, res) => {
  const filePath = path.join(HANDSHAKES_DIR, req.params.file);
  if (fs.existsSync(filePath)) {
    res.download(filePath);
  } else {
    res.status(404).send('File not found');
  }
});

const removeIncorrectPassword = (potfilePath, ssid, password) => {
  if (fs.existsSync(potfilePath)) {
    const data = fs.readFileSync(potfilePath, 'utf-8');
    const lines = data.split('\n');
    const filteredLines = lines.filter(line => !line.includes(`${ssid}:${password}`));
    fs.writeFileSync(potfilePath, filteredLines.join('\n'));
  }
};

// Function to send a message to a Discord webhook
const sendDiscordMessage = (webhookUrl, message) => {
  const payload = JSON.stringify({ content: message });
  const options = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  };

  fetch(webhookUrl, { ...options, body: payload })
    .then(response => {
      if (!response.ok) {
        console.error('Error sending Discord message:', response.statusText);
      }
    })
    .catch(error => {
      console.error('Error sending Discord message:', error);
    });
};

// Submit results endpoint
app.post('/put_work', (req, res) => {
  const { file_name, potfile_content } = req.body;
  
  if (!file_name || !potfile_content) {
    console.error("Missing parameters");
    return res.status(400).json({ error: 'Missing parameters' });
  }

  // Extract hash from the filename
  const hashFileName = path.basename(file_name, '.potfile');
  const hash = hashFileName.split('.')[0];

  // Find the user who uploaded the hash
  db.query(`SELECT \`key\`, hash FROM hash_data WHERE file_name = ?`, [`${hash}.hc22000`], (err, rows) => {
    if (err) {
      console.error("Error finding user key:", err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (!rows.length) {
      console.error("User not found for the given file");
      return res.status(404).json({ error: 'User not found for the given file' });
    }

    const userKey = rows[0].key;
    const dbHash = rows[0].hash;

    // Find the user's email
    db.query(`SELECT email, discord_webhook_url, display_cracked_content FROM users WHERE \`key\` = ?`, [userKey], (err, userRows) => {
      if (err) {
        console.error("Error finding user email:", err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!userRows.length) {
        console.error("Email not found for the given user key");
        return res.status(404).json({ error: 'Email not found for the given user key' });
      }

      const userEmail = userRows[0].email;
      const discordWebhookUrl = userRows[0].discord_webhook_url;
      const displayCrackedContent = userRows[0].display_cracked_content === 'true';
      const userPotfilePath = path.join(RESULTS_DIR, `${userEmail}.potfile`);

      // Extract SSID and password from potfile content
      const crackedPasswords = potfile_content.split('\n').map(line => {
        const parts = line.split(':');
        if (parts.length === 5) {
          return {
            SSID: parts[3],
            password: parts[4]
          };
        }
        return null;
      }).filter(result => result !== null);

      // Debug: Log the cracked passwords
      console.log("Cracked Passwords:", crackedPasswords);

      // Update hash_data table with SSID and password
      crackedPasswords.forEach(({ SSID, password }) => {
        if (password && password.length >= 8) {
          testPasswordWithHashcat(dbHash, password, (isCorrect) => {
            if (isCorrect) {
              db.query(`UPDATE hash_data SET SSID = ?, password = ? WHERE hash = ? AND \`key\` = ?`, [SSID, password, dbHash, userKey], (err) => {
                if (err) {
                  console.error("Error updating hash data:", err);
                } else {
                  // Debug: Log successful update
                  console.log(`Updated hash_data for hash: ${dbHash}, SSID: ${SSID}, password: ${password}`);
                }
              });

              // Check if the same hash has been uploaded by another user and has a password
              db.query(`SELECT \`key\` FROM hash_data WHERE hash = ? AND \`key\` != ? AND password IS NULL`, [dbHash, userKey], (err, otherRows) => {
                if (err) {
                  console.error("Error checking for duplicate hash:", err);
                } else if (otherRows.length) {
                  // Update the other user's entry with the password
                  db.query(`UPDATE hash_data SET password = ? WHERE hash = ? AND \`key\` = ?`, [password, dbHash, otherRows[0].key], (err) => {
                    if (err) {
                      console.error("Error updating duplicate hash data:", err);
                    } else {
                      console.log(`Copied password to duplicate hash entry for key: ${otherRows[0].key}`);
                    }
                  });
                }
              });

              // Move handshake file to processed
              const source = path.join(HANDSHAKES_DIR, `${hash}.hc22000`);
              const destination = path.join(PROCESSED_DIR, `${hash}.hc22000`);
              
              if (fs.existsSync(source)) {
                fs.renameSync(source, destination);
              }

              // Save to boss potfile
              try {
                fs.appendFileSync(bossPotfilePath, potfile_content + '\n');
              } catch (err) {
                console.error("Error saving to boss potfile:", err);
                return res.status(500).json({ error: 'Error saving to boss potfile' });
              }

              // Save to user's potfile
              try {
                fs.appendFileSync(userPotfilePath, potfile_content + '\n');
              } catch (err) {
                console.error("Error saving to user's potfile:", err);
                return res.status(500).json({ error: 'Error saving to user\'s potfile' });
              }

              // Send Discord notification if webhook URL is set
              if (discordWebhookUrl) {
                let message = 'You have a new cracked handshake!';
                if (displayCrackedContent) {
                  message += `\nSSID: ${SSID}\nPassword: ${password}`;
                }
                sendDiscordMessage(discordWebhookUrl, message);
              }

              res.json({ success: true });
            } else {
              console.error(`Password ${password} is incorrect for hash ${dbHash}`);
              // Remove incorrect SSID:password combination from potfiles
              removeIncorrectPassword(bossPotfilePath, SSID, password);
              removeIncorrectPassword(userPotfilePath, SSID, password);
              // Immediately hand out the file again
              getFileWithLowestCount((file) => {
                if (!file) {
                  return res.status(404).json({ error: 'No work available' });
                }

                // Update counter and last_assigned timestamp
                db.query(`UPDATE hash_data SET counter = counter + 1, last_assigned = CURRENT_TIMESTAMP WHERE file_name = ?`, [file], (err) => {
                  if (err) {
                    console.error("Error updating counter:", err);
                  }
                });

                res.json({ 
                  success: false, 
                  error: 'Incorrect password', 
                  new_work: { 
                    file_name: file, 
                    download_url: `http://${req.headers.host}/download/${file}` 
                  } 
                });
              });
            }
          });
        } else {
          console.error(`Password ${password} is too short for hash ${dbHash}`);
          // Immediately hand out the file again
          getFileWithLowestCount((file) => {
            if (!file) {
              return res.status(404).json({ error: 'No work available' });
            }

            // Update counter and last_assigned timestamp
            db.query(`UPDATE hash_data SET counter = counter + 1, last_assigned = CURRENT_TIMESTAMP WHERE file_name = ?`, [file], (err) => {
              if (err) {
                console.error("Error updating counter:", err);
              }
            });

            res.json({ 
              success: false, 
              error: 'Password too short', 
              new_work: { 
                file_name: file, 
                download_url: `http://${req.headers.host}/download/${file}` 
              } 
            });
          });
        }
      });
    });
  });
});

// Middleware to parse JSON requests
app.use(bodyParser.json());
app.use(express.static('public'));

// Session middleware
app.use(session({
    secret: 'SESSION_SECRET_PLACEHOLDER', // replaced session secret with placeholder
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set secure: true when using HTTPS in production
}));

// Ensure the upload directory exists
const uploadDir = path.join(__dirname, 'handshakes');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure Multer storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    }
});

// File filter to allow only .hc22000 files
const fileFilter = (req, file, cb) => {
    if (!file.originalname.endsWith('.hc22000')) {
        return cb(new Error('Only .hc22000 files are allowed'), false);
    }
    cb(null, true);
};

const upload = multer({ storage, fileFilter });

// Function to save key to database
const saveKeyToFile = (email, key, callback) => {
  db.query(`SELECT email FROM users WHERE email = ?`, [email], (err, rows) => {
    if (err) {
      console.error("Error checking email in database:", err);
      callback(err);
      return;
    }
    if (rows.length) {
      callback(new Error("Email already in use"));
    } else {
      db.query(`INSERT INTO users (email, \`key\`) VALUES (?, ?)`, [email, key], (err) => {
        if (err) {
          console.error("Error saving key to database:", err);
          callback(err);
        } else {
          callback(null);
        }
      });
    }
  });
};

// Function to log uploads per user
const logUpload = (email, fileName) => {
  const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
  db.query(`INSERT INTO upload_logs (email, file_name, timestamp) VALUES (?, ?, ?)`, [email, fileName, timestamp]);
};

// Middleware to check if user is logged in (for restricted actions)
const isLoggedIn = (req, res, next) => {
    if (!req.session.key) {
        return res.status(401).json({ error: "Unauthorized: You must be logged in to upload." });
    }
    next();
};

// Route: Home Page
app.get('/', (req, res) => {
  const filePath = path.join(__dirname, 'public', 'index.html');
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).send('Error reading index.html');
    }
    res.send(data);
  });
});

// Route: About Page
app.get('/about', (req, res) => {
  const filePath = path.join(__dirname, 'public', 'about.html');
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).send('Error reading about.html');
    }
    res.send(data);
  });
});

// Route: Submit Page (with warning if not logged in)
app.get('/submit', (req, res) => {
  const filePath = path.join(__dirname, 'public', 'submit.html');
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).send('Error reading submit.html');
    }
    res.send(data);
  });
});

// Function to generate random file name
const generateRandomFileName = (length) => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
};

// Route: Handle File Upload (Requires Login)
app.post('/upload', isLoggedIn, upload.single('handshake'), (req, res) => {
  // Log the upload: retrieve the email for the logged-in key and record the file name
  findKeyInDB(req.session.key, async (keyData) => {
    if (!keyData) {
      return res.status(400).json({ error: 'Invalid session key.' });
    }
    // Define initial counter based on VIP rank
    const initialCounter = keyData.rank === 'VIP' ? -1 : 0;
    if (keyData) {
      logUpload(keyData.email, req.file.originalname);
      
      // Generate random filenames for the hashes
      const filenames = [];
      for (let i = 0; i < 10; i++) {  // Assuming a maximum of 10 hashes per file
        filenames.push(`${generateRandomFileName(12)}.hc22000`);
      }

      // Extract hashes from the uploaded file
      try {
        const hashes = await extractHashesFromHC22000(req.file.path, req.session.key, filenames);
        // Get the latest index for the user key
        db.query(`SELECT MAX(CAST(SUBSTR(file_name, INSTR(file_name, '-') + 1, LENGTH(file_name) - INSTR(file_name, '-') - 8) AS UNSIGNED)) AS maxIndex FROM hash_data WHERE \`key\` = ?`, [req.session.key], (err, rows) => {
          if (err) {
            console.error("Error fetching max index:", err);
            return;
          }

          let startIndex = rows[0].maxIndex ? rows[0].maxIndex + 1 : 1;

          // Log each hash for the user, avoiding duplicates
          hashes.forEach((hash, index) => {
            const fileName = filenames[index];
            db.query(`SELECT * FROM hash_data WHERE \`key\` = ? AND hash = ?`, [req.session.key, hash], (err, rows) => {
              if (err) {
                console.error("Error checking for duplicate hash:", err);
              } else if (!rows.length) {
                db.query(`INSERT INTO hash_data (\`key\`, hash, file_name, counter) VALUES (?, ?, ?, ?)`, [req.session.key, hash, fileName, initialCounter], (err) => {
                  if (!err) {
                    updateSSIDAndBSSIDForHash(req.session.key, hash);  // Update SSID and BSSID for the new hash
                  }
                });

                // Check if the same hash has been uploaded by another user and has a password
                db.query(`SELECT password FROM hash_data WHERE hash = ? AND \`key\` != ? AND password IS NOT NULL`, [hash, req.session.key], (err, otherRows) => {
                  if (err) {
                    console.error("Error checking for duplicate hash:", err);
                  } else if (otherRows.length) {
                    // Update the new entry with the password from the other user
                    db.query(`UPDATE hash_data SET password = ? WHERE hash = ? AND \`key\` = ?`, [otherRows[0].password, hash, req.session.key], (err) => {
                      if (err) {
                        console.error("Error updating duplicate hash data:", err);
                      } else {
                        console.log(`Copied password to new hash entry for key: ${req.session.key}`);
                      }
                    });
                  }
                });
              }
            });
          });
        });
      } catch (error) {
        console.error("Error extracting hashes:", error);
      }
    }
    res.set('Content-Type', 'text/html');
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <title>Upload Successful</title>
      </head>
      <body>
        <h1>File Uploaded Successfully</h1>
        <a href="/submit">Upload Another</a>
        <a href="/nets">View Uploaded Files</a>
      </body>
      </html>
    `);
  });
});

// Add an endpoint to handle file uploads from the Pwncrack plugin
app.post('/upload_handshake', upload.single('handshake'), (req, res) => {
  const { key } = req.body;
  if (!key) {
    return res.status(400).json({ error: 'Bad Request: No key provided.' });
  }

  // Log the upload: retrieve the email for the logged-in key and record the file name
  findKeyInDB(key, async (keyData) => {
    if (!keyData) {
      return res.status(400).json({ error: 'Invalid session key.' });
    }
    logUpload(keyData.email, req.file.originalname);

    // Define initial counter based on VIP rank
    const initialCounter = keyData.rank === 'VIP' ? -1 : 0;

    // Generate random filenames for the hashes
    const filenames = [];
    for (let i = 0; i < 10; i++) {  // Assuming a maximum of 10 hashes per file
      filenames.push(`${generateRandomFileName(12)}.hc22000`);
    }

    // Extract hashes from the uploaded file
    try {
      const hashes = await extractHashesFromHC22000(req.file.path, key, filenames);
      // Get the latest index for the user key
      db.query(`SELECT MAX(CAST(SUBSTR(file_name, INSTR(file_name, '-') + 1, LENGTH(file_name) - INSTR(file_name, '-') - 8) AS UNSIGNED)) AS maxIndex FROM hash_data WHERE \`key\` = ?`, [key], (err, rows) => {
        if (err) {
          console.error("Error fetching max index:", err);
          return;
        }

        let startIndex = rows[0].maxIndex ? rows[0].maxIndex + 1 : 1;

        // Log each hash for the user, avoiding duplicates
        hashes.forEach((hash, index) => {
          const fileName = filenames[index];
          db.query(`SELECT * FROM hash_data WHERE \`key\` = ? AND hash = ?`, [key, hash], (err, rows) => {
            if (err) {
              console.error("Error checking for duplicate hash:", err);
            } else if (!rows.length) {
              db.query(`INSERT INTO hash_data (\`key\`, hash, file_name, counter) VALUES (?, ?, ?, ?)`, [key, hash, fileName, initialCounter], (err) => {
                if (!err) {
                  updateSSIDAndBSSIDForHash(key, hash);  // Update SSID and BSSID for the new hash
                }
              });

              // Check if the same hash has been uploaded by another user and has a password
              db.query(`SELECT password FROM hash_data WHERE hash = ? AND \`key\` != ? AND password IS NOT NULL`, [hash, key], (err, otherRows) => {
                if (err) {
                  console.error("Error checking for duplicate hash:", err);
                } else if (otherRows.length) {
                  // Update the new entry with the password from the other user
                  db.query(`UPDATE hash_data SET password = ? WHERE hash = ? AND \`key\` = ?`, [otherRows[0].password, hash, key], (err) => {
                    if (err) {
                      console.error("Error updating duplicate hash data:", err);
                    } else {
                      console.log(`Copied password to new hash entry for key: ${key}`);
                    }
                  });
                }
              });
            }
          });
        });
      });
    } catch (error) {
      console.error("Error extracting hashes:", error);
    }
    res.json({ success: true });
  });
});

// Route: Display Uploaded Files (nets.html)
app.get('/nets', (req, res) => {
    fs.readdir(uploadDir, (err, files) => {
        if (err) {
            return res.status(500).send('Error reading directory.');
        }
        const fileLinks = files
            .filter(file => file.endsWith('.hc22000'))
            .map(file => `<li><a href="/handshakes/${file}" download>${file}</a></li>`)
            .join('');
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <title>Uploaded Handshakes</title>
            </head>
            <body>
                <h1>Available .hc22000 Files</h1>
                <ul>${fileLinks}</ul>
                <a href="/">Back to Home</a>
            </body>
            </html>
        `);
    });
});

// Serve uploaded files
app.use('/handshakes', express.static(uploadDir));
app.use('/wordlists', express.static(WORDLISTS_DIR));

// Global Error Handler (Improved for HTML)
app.use((err, req, res, next) => {
    if (err) {
        res.status(400);
        res.set('Content-Type', 'text/html');
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <title>Upload Error</title>
            </head>
            <body>
                <h1>Upload Error</h1>
                <p>${err.message}</p>
                <a href="/submit">Go Back</a>
            </body>
            </html>
        `);
    } else {
        next();
    }
});

// Route to send the list of files as JSON (for client-side JavaScript)
app.get('/list', (req, res) => {
    fs.readdir(uploadDir, (err, files) => {
        if (err) {
            return res.status(500).json({ error: 'Error reading directory' });
        }
        const fileList = files.filter(file => file.endsWith('.hc22000'));
        res.json(fileList);
    });
});

// Endpoint to request a unique key (with email validation)
app.post('/request-key', (req, res) => {
    const { email } = req.body;
    if (!email || !validateEmail(email)) {
        return res.status(400).json({ error: 'Invalid email address' });
    }
    const key = uuid.v4();
    saveKeyToFile(email, key, (err) => {
        if (err) {
            if (err.message === "Email already in use") {
                return res.status(400).json({ error: 'Email already in use. Try to regenerate if you lost your key.' });
            }
            return res.status(500).json({ error: 'Internal server error' });
        }
        // Send email with the key
        const subject = 'PWNcrack key';
        const message = `Thank you for signing up! Your key is: ${key}`;
        sendEmail(email, subject, message);
        res.json({ key: key });
    });
});

// Endpoint to login with a key
app.post('/login', (req, res) => {
    const { key } = req.body;
    findKeyInDB(key, (keyData) => {
        if (keyData) {
            req.session.key = key;
            res.json({ success: true });
        } else {
            res.status(400).json({ success: false });
        }
    });
});

// Endpoint to logout (destroy session)
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ success: false });
        }
        res.json({ success: true });
    });
});

// Endpoint to get current session status
app.get('/status', (req, res) => {
    res.json({ loggedIn: !!req.session.key, key: req.session.key || null });
});

// Function to validate email format
const validateEmail = (email) => {
    const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return re.test(email);
};

// Function to find key from the database
const findKeyInDB = (key, callback) => {
  db.query(`SELECT * FROM users WHERE \`key\` = ?`, [key], (err, rows) => {
    if (err) {
      console.error(err);
      callback(null);
    } else {
      callback(rows[0]);
    }
  });
};

// Middleware to inject login status into every page (for server-side rendering, if applicable)
app.use((req, res, next) => {
    res.locals.isLoggedIn = !!req.session.key;
    res.locals.key = req.session.key || null;
    next();
});

// Function to get total hashes uploaded
const getTotalHashesUploaded = (callback) => {
  db.query(`SELECT COUNT(hash) AS total FROM hash_data`, (err, rows) => {
    if (err) {
      console.error(err);
      callback(0);
    } else {
      callback(rows[0].total);
    }
  });
};

// Function to get total passwords cracked
const getTotalPasswordsCracked = (callback) => {
  db.query(`SELECT COUNT(*) AS total FROM hash_data WHERE password IS NOT NULL`, (err, rows) => {
    if (err) {
      console.error(err);
      callback(0);
    } else {
      callback(rows[0].total);
    }
  });
};

// Function to get total unique hashes uploaded
const getTotalUniqueHashesUploaded = (callback) => {
  db.query(`SELECT COUNT(DISTINCT hash) AS total FROM hash_data WHERE hash IS NOT NULL AND hash != ''`, (err, rows) => {
    if (err) {
      console.error(err);
      callback(0);
    } else {
      callback(rows[0].total);
    }
  });
};

// Function to calculate success rate
const calculateSuccessRate = (totalHashes, totalCracked) => {
    return totalHashes === 0 ? 0 : ((totalCracked / totalHashes) * 100).toFixed(2);
};

// Endpoint to get statistics
app.get('/stats', (req, res) => {
    getTotalHashesUploaded((totalHashes) => {
        getTotalPasswordsCracked((totalCracked) => {
            getTotalUniqueHashesUploaded((totalUniqueHashes) => {
                const successRate = calculateSuccessRate(totalHashes, totalCracked);
                res.json({
                    totalHashes: totalHashes,
                    totalCracked: totalCracked,
                    totalUniqueHashes: totalUniqueHashes,
                    successRate: successRate
                });
            });
        });
    });
});

// Endpoint to get unique hashes count for the logged-in user
app.get('/unique_hashes_count', (req, res) => {
    const userKey = req.query.key;
    if (!userKey) {
        return res.status(400).json({ error: 'Bad Request: No key provided.' });
    }

    db.query(`SELECT COUNT(DISTINCT hash) AS count FROM hash_data WHERE \`key\` = ?`, [userKey], (err, rows) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Error fetching unique hashes count' });
        }
        res.json({ count: rows[0].count });
    });
});

// Endpoint to download hashes for the logged-in user
app.get('/download_hashes', (req, res) => {
    const userKey = req.query.key;
    if (!userKey) {
        return res.status(400).json({ error: 'Bad Request: No key provided.' });
    }

    findKeyInDB(userKey, (keyData) => {
        if (!keyData) {
            return res.status(400).json({ error: 'Invalid session key.' });
        }

        const tempDirBase = path.join(os.tmpdir(), 'hashes');
        if (!fs.existsSync(tempDirBase)) {
            fs.mkdirSync(tempDirBase, { recursive: true });
        }

        const tempFilePath = path.join(tempDirBase, `${userKey}.hc22000`);
        db.query(`SELECT hash FROM hash_data WHERE \`key\` = ?`, [userKey], (err, rows) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Error fetching hashes' });
            }

            const hashes = rows.map(row => row.hash).join('\n');
            fs.writeFile(tempFilePath, hashes, (err) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ error: 'Error writing hashes to file' });
                }

                res.download(tempFilePath, `${userKey}.hc22000`, (err) => {
                    if (err) {
                        console.error('Error downloading the file:', err);
                    }
                    fs.unlink(tempFilePath, (err) => {
                        if (err) {
                            console.error('Error deleting the temporary file:', err);
                        }
                    });
                });
            });
        });
    });
});

// Endpoint to download uncracked hashes for the logged-in user
app.get('/download_uncracked_hashes', (req, res) => {
  const userKey = req.query.key;
  if (!userKey) {
    return res.status(400).json({ error: 'Bad Request: No key provided.' });
  }

  findKeyInDB(userKey, (keyData) => {
    if (!keyData) {
      return res.status(400).json({ error: 'Invalid session key.' });
    }

    const tempDirBase = path.join(os.tmpdir(), 'hashes');
    if (!fs.existsSync(tempDirBase)) {
      fs.mkdirSync(tempDirBase, { recursive: true });
    }

    const tempFilePath = path.join(tempDirBase, `${userKey}_uncracked.hc22000`);
    db.query(`SELECT hash FROM hash_data WHERE \`key\` = ? AND password IS NULL`, [userKey], (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error fetching hashes' });
      }

      const hashes = rows.map(row => row.hash).join('\n');
      fs.writeFile(tempFilePath, hashes, (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Error writing hashes to file' });
        }

        res.download(tempFilePath, `${userKey}_uncracked.hc22000`, (err) => {
          if (err) {
            console.error('Error downloading the file:', err);
          }
          fs.unlink(tempFilePath, (err) => {
            if (err) {
              console.error('Error deleting the temporary file:', err);
            }
          });
        });
      });
    });
  });
});

app.get('/user_hashes', (req, res) => {
  const userKey = req.query.key;
  if (!userKey) {
    return res.status(400).json({ error: 'Bad Request: No key provided.' });
  }

  findKeyInDB(userKey, (keyData) => {
    if (!keyData) {
      return res.status(400).json({ error: 'Invalid session key.' });
    }

    if (keyData.display !== 'true') {
      return res.status(403).json({ error: 'Forbidden: Display not enabled for this user.' });
    }

    db.query(`SELECT hash, SSID, password FROM hash_data WHERE \`key\` = ?`, [userKey], (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error fetching user hashes' });
      }

      res.json(rows);
    });
  });
});

// Function to reset assigned status after 10 minutes
const resetAssignedStatus = () => {
  const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  db.query(`SELECT file_name, counter FROM hash_data WHERE last_assigned < ?`, [tenMinutesAgo], (err, rows) => {
    if (err) {
      console.error("Error fetching old assignments:", err);
      return;
    }

    rows.forEach(row => {
      // Commented out deletion/not found logic
      /*
      if (row.counter >= 6) {
        const source = path.join(HANDSHAKES_DIR, row.file_name);
        const destination = path.join(NOT_FOUND_DIR, row.file_name);
        if (fs.existsSync(source)) {
          fs.renameSync(source, destination);
          // Update the password to "not found" in the database
          db.query(`UPDATE hash_data SET password = 'not found' WHERE file_name = ?`, [row.file_name], (err) => {
            if (err) {
              console.error("Error updating password to 'not found':", err);
            }
          });
        }
      }
      */
    });
  });
};

// Schedule the reset function to run every 10 minutes
setInterval(resetAssignedStatus, 10 * 60 * 1000);

const uploadSettings = multer();

// Endpoint to update user settings
app.post('/update-settings', uploadSettings.none(), (req, res) => {
  const { key, theme, display, username, leaderboard, BSSID_display, discord_webhook_url, display_cracked_content } = req.body;
  console.log('Received settings update request:', req.body); // Log the received data

  if (!key) {
    return res.status(400).json({ error: 'Bad Request: No key provided.' });
  }

  // Check if the username is already taken
  if (username) {
    db.query(`SELECT * FROM users WHERE username = ? AND \`key\` != ?`, [username, key], (err, rows) => {
      if (err) {
        console.error("Error checking username:", err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (rows.length) {
        return res.status(400).json({ error: 'Username already taken' });
      }

      // Update user settings if the username is not taken
      db.query(`UPDATE users SET theme = ?, display = ?, username = ?, leaderboard = ?, \`BSSID_display\` = ?, discord_webhook_url = ?, display_cracked_content = ? WHERE \`key\` = ?`, [theme, display, username, leaderboard, BSSID_display, discord_webhook_url, display_cracked_content, key], (err) => {
        if (err) {
          console.error("Error updating user settings:", err);
          return res.status(500).json({ error: 'Internal server error' });
        }
        res.json({ success: true });
      });
    });
  } else {
    // Update user settings if no username is provided
    db.query(`UPDATE users SET theme = ?, display = ?, username = ?, leaderboard = ?, \`BSSID_display\` = ?, discord_webhook_url = ?, display_cracked_content = ? WHERE \`key\` = ?`, [theme, display, username, leaderboard, BSSID_display, discord_webhook_url, display_cracked_content, key], (err) => {
      if (err) {
        console.error("Error updating user settings:", err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.json({ success: true });
    });
  }
});

app.post('/delete_hash', (req, res) => {
  const { hash, key } = req.body;
  if (!hash || !key) {
    return res.status(400).json({ error: 'Bad Request: Missing parameters.' });
  }

  findKeyInDB(key, (keyData) => {
    if (!keyData) {
      return res.status(400).json({ error: 'Invalid session key.' });
    }

    db.query(`SELECT file_name FROM hash_data WHERE hash = ? AND \`key\` = ?`, [hash, key], (err, rows) => {
      if (err) {
        console.error("Error finding file name:", err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!rows.length) {
        return res.status(404).json({ error: 'Hash not found.' });
      }

      const filePath = path.join(HANDSHAKES_DIR, rows[0].file_name);

      db.query(`DELETE FROM hash_data WHERE hash = ? AND \`key\` = ?`, [hash, key], (err) => {
        if (err) {
          console.error("Error deleting hash:", err);
          return res.status(500).json({ error: 'Internal server error' });
        }

        if (fs.existsSync(filePath)) {
          fs.unlink(filePath, (err) => {
            if (err) {
              console.error("Error deleting file:", err);
              return res.status(500).json({ error: 'Internal server error' });
            }
            res.json({ success: true });
          });
        } else {
          res.json({ success: true });
        }
      });
    });
  });
});

// Route to serve the selected CSS file based on the user's theme
app.get('/user-theme.css', (req, res) => {
  const userKey = req.query.key;
  if (!userKey) {
    return res.status(400).send('Bad Request: No key provided.');
  }

  findKeyInDB(userKey, (keyData) => {
    if (!keyData) {
      return res.status(400).send('Invalid session key.');
    }

    const theme = keyData.theme ? keyData.theme.toLowerCase().replace('/', '-') : 'styles'; // Default theme if none is set
    const themeFilePath = path.join(__dirname, 'public', 'css', `${theme}.css`);

    if (fs.existsSync(themeFilePath)) {
      fs.readFile(themeFilePath, 'utf8', (err, data) => {
        if (err) {
          return res.status(500).send('Error reading theme file.');
        }

        // Add !important to each CSS rule
        const importantCSS = data.replace(/(;|})/g, ' !important$1');

        res.setHeader('Content-Type', 'text/css');
        res.send(importantCSS);
      });
    } else {
      res.status(404).send('Theme not found.');
    }
  });
});

// Serve the CSS loader script
app.get('/js/css-loader.js', (req, res) => {
  const filePath = path.join(__dirname, 'public', 'js', 'css-loader.js');
  res.sendFile(filePath);
});

app.post('/update_hashrate', (req, res) => {
  const { file_name, hashrate, cracker_id, user_key } = req.body;
  console.log('Received hashrate update:', { file_name, hashrate, cracker_id, user_key }); // Debug log
  
  if (!file_name || hashrate === undefined || !cracker_id || !user_key) {
    console.error('Missing parameters in hashrate update');
    return res.status(400).json({ error: 'Bad Request: Missing parameters.' });
  }
  
  // Check if there's an existing timestamp for this cracker_id and user_key pair
  db.query(
    `SELECT timestamp FROM hash_rate WHERE cracker_id = ? AND user_key = ? ORDER BY timestamp DESC LIMIT 1`,
    [cracker_id, user_key],
    (err, rows) => {
      if (err) {
        console.error("Error fetching timestamp:", err);
        return res.status(500).json({ error: 'Database error' });
      }
  
      const now = new Date();
      let sessionTime = 0;
  
      if (rows.length > 0) {
        const lastTimestamp = new Date(rows[0].timestamp);
        const diffSeconds = Math.floor((now - lastTimestamp) / 1000);
  
        if (diffSeconds < 60) {
          sessionTime = diffSeconds;
        } else {
          // If the last update was more than a minute ago, reset session time for this user
          db.query(
            `DELETE FROM hash_rate WHERE cracker_id = ? AND user_key = ? AND timestamp = ?`,
            [cracker_id, user_key, rows[0].timestamp],
            (err) => {
              if (err) {
                console.error("Error deleting old timestamp:", err);
              }
            }
          );
        }
      }
  
      // Insert new hashrate record for this user
      db.query(
        `INSERT INTO hash_rate 
         (user_key, cracker_id, file_name, hashrate, processed_hashes, session_time, timestamp) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [user_key, cracker_id, file_name, hashrate, Math.floor(hashrate * sessionTime), sessionTime, now],
        (err) => {
          if (err) {
            console.error("Error inserting hashrate:", err);
            return res.status(500).json({ error: 'Database error' });
          }
          console.log(`Successfully stored hashrate for user ${user_key}`);
          res.json({ success: true });
        }
      );
    }
  );
});

// Update the total hashrate endpoint to use the database
app.get('/total_hashrate', (req, res) => {
  db.query(
    `SELECT SUM(latest_hashrate) as total_hashrate FROM (
       SELECT MAX(hashrate) as latest_hashrate 
       FROM hash_rate 
       WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)
       GROUP BY user_key
     ) as subquery`,
    (err, rows) => {
      if (err) {
        console.error("Error fetching total hashrate:", err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.json({ totalHashrate: rows[0].total_hashrate || 0 });
    }
  );
});

// Function to extract passwords from boss.potfile and write to cracked.txt without duplicates
const generateCrackedPasswordsFile = () => {
  fs.readFile(bossPotfilePath, 'utf-8', (err, data) => {
    if (err) {
      console.error("Error reading boss.potfile:", err);
      return;
    }

    const passwords = new Set(data.split('\n').map(line => {
      const parts = line.split(':');
      if (parts.length === 5) {
        return parts[4]; // Extract the password part
      }
      return null;
    }).filter(password => password !== null));

    const crackedFilePath = path.join(RESULTS_DIR, 'cracked.txt');
    fs.readFile(crackedFilePath, 'utf-8', (err, existingData) => {
      if (err && err.code !== 'ENOENT') {
        console.error("Error reading cracked.txt:", err);
        return;
      }

      if (existingData) {
        existingData.split('\n').forEach(password => passwords.add(password));
      }

      fs.writeFile(crackedFilePath, Array.from(passwords).join('\n'), (err) => {
        if (err) {
          console.error("Error writing cracked.txt:", err);
        }
      });
    });
  });
};

// Schedule the function to run every 10 seconds
setInterval(generateCrackedPasswordsFile, 10 * 1000); // 10 seconds in milliseconds

app.get('/user-settings', (req, res) => {
  const userKey = req.query.key;
  if (!userKey) {
    return res.status(400).json({ error: 'Bad Request: No key provided.' });
  }

  findKeyInDB(userKey, (keyData) => {
    if (!keyData) {
      return res.status(400).json({ error: 'Invalid session key.' });
    }

    res.json({
      success: true,
      theme: keyData.theme,
      display: keyData.display,
      username: keyData.username,
      leaderboard: keyData.leaderboard,
      BSSID_display: keyData.BSSID_display,
      discord_webhook_url: keyData.discord_webhook_url,
      display_cracked_content: keyData.display_cracked_content
    });
  });
});

app.get('/leaderboard', (req, res) => {
  const sortBy = req.query.sortBy || 'hashesCracked';
  const sortColumn = sortBy === 'uploadedHashes' ? 'uploadedHashes' : sortBy === 'percentCracked' ? 'percentCracked' : 'hashesCracked';

  db.query(`
    SELECT 
      \`key\`, 
      COUNT(*) AS uploadedHashes,
      SUM(CASE WHEN password IS NOT NULL THEN 1 ELSE 0 END) AS hashesCracked 
    FROM hash_data 
    GROUP BY \`key\` 
  `, (err, hashRows) => {
    if (err) {
      console.error("Error fetching leaderboard data:", err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    const keys = hashRows.map(row => row.key);
    if (keys.length === 0) {
      return res.json([]);
    }

    db.query(`SELECT \`key\`, username, \`rank\` FROM users WHERE \`key\` IN (${keys.map(() => '?').join(',')})`, keys, (err, userRows) => {
      if (err) {
        console.error("Error fetching user data:", err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      const userMap = userRows.reduce((acc, user) => {
        acc[user.key] = { username: user.username, rank: user.rank };
        return acc;
      }, {});

      const leaderboard = hashRows
        .filter(row => userMap[row.key]) // Only include entries with a username
        .map(row => {
          const user = userMap[row.key];
          const username = user.rank === 'VIP' ? `[VIP] ${user.username}` : user.username;
          const percentCracked = row.uploadedHashes === 0 ? 0 : ((row.hashesCracked / row.uploadedHashes) * 100).toFixed(2);
          return {
            username: username || 'Unknown',
            uploadedHashes: row.uploadedHashes,
            hashesCracked: row.hashesCracked,
            percentCracked: percentCracked,
            rank: user.rank // Include rank in the response
          };
        });

      leaderboard.sort((a, b) => b[sortColumn] - a[sortColumn]);

      res.json(leaderboard);
    });
  });
});

// Endpoint to regenerate a key if the user loses it
app.post('/regenerate-key', (req, res) => {
    const { email } = req.body;
    if (!email || !validateEmail(email)) {
        return res.status(400).json({ error: 'Invalid email address' });
    }

    db.query(`SELECT email, \`key\` FROM users WHERE email = ?`, [email], (err, rows) => {
        if (err) {
            console.error("Error checking email in database:", err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        if (!rows.length) {
            return res.status(404).json({ error: 'Email not found' });
        }

        const oldKey = rows[0].key;
        const newKey = uuid.v4();

        db.query(`UPDATE users SET \`key\` = ? WHERE email = ?`, [newKey, email], (err) => {
            if (err) {
                console.error("Error updating key in database:", err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            // Send email with the new key
            const subject = 'PWNcrack key';
            const message = `Your key has been regenerated. Your new key is: ${newKey}`;
            sendEmail(email, subject, message);
            console.log(`Key regenerated for email: ${email}`);
            res.json({ key: newKey });
             });

            // Update key in hash_data table
            db.query(`UPDATE hash_data SET \`key\` = ? WHERE \`key\` = ?`, [newKey, oldKey], (err) => {
                if (err) {
                    console.error("Error updating key in hash_data table:", err);
                    return res.status(500).json({ error: 'Internal server error' });
                }

                // Update key in upload_logs table
                db.query(`UPDATE upload_logs SET email = ? WHERE email = ?`, [newKey, oldKey], (err) => {
                    if (err) {
                        console.error("Error updating key in upload_logs table:", err);
                        return res.status(500).json({ error: 'Internal server error' });
                    }
            });
        });
    });
});

// Configure nodemailer without exposing personal email credentials
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'EMAIL_ADDRESS_PLACEHOLDER',  // replaced email address with placeholder
    pass: 'EMAIL_PASSWORD_PLACEHOLDER'    // replaced email password with placeholder
  },
  tls: {
    rejectUnauthorized: false
  }
});

// Function to send email
const sendEmail = (email, subject, message) => {
  const mailOptions = {
    from: 'EMAIL_ADDRESS_PLACEHOLDER',  // replaced from address with placeholder
    to: email,
    subject: subject,
    text: message
  };

  console.log('Sending email with the following options:', mailOptions);  // Log the email options

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
};

// Function to delete files not listed in the hash database
function deleteUnlistedFiles() {
  fs.readdir(HANDSHAKES_DIR, (err, files) => {
    if (err) {
      console.error("Error reading handshakes directory:", err);
      return;
    }

    db.query(`SELECT file_name FROM hash_data`, (err, rows) => {
      if (err) {
        console.error("Error fetching file names from database:", err);
        return;
      }

      const dbFiles = new Set(rows.map(row => row.file_name));
      files.forEach(file => {
        if (!dbFiles.has(file)) {
          const filePath = path.join(HANDSHAKES_DIR, file);
          fs.unlink(filePath, (err) => {
            if (err) {
              console.error(`Error deleting file ${file}:`, err);
            } else {
              console.log(`Deleted file ${file}`);
            }
          });
        }
      });
    });
  });
}

// Schedule the function to run every minute
setInterval(deleteUnlistedFiles, 60 * 1000);

app.post('/submit_password', (req, res) => {
  const { ssid, password, key } = req.body;
  if (!ssid || !password || !key) {
    console.error('Missing parameters:', { ssid, password, key });
    return res.status(400).json({ error: 'Bad Request: Missing parameters.' });
  }

  findKeyInDB(key, (keyData) => {
    if (!keyData) {
      console.error('Invalid session key:', key);
      return res.status(400).json({ error: 'Invalid session key.' });
    }

    db.query(`SELECT hash FROM hash_data WHERE SSID = ? AND \`key\` = ?`, [ssid, key], (err, rows) => {
      if (err) {
        console.error('Error finding hash:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!rows.length) {
        console.error('SSID not found:', ssid);
        return res.status(404).json({ error: 'SSID not found.' });
      }

      const hash = rows[0].hash;
      testPasswordWithHashcat(hash, password, (isCorrect) => {
        if (isCorrect) {
          db.query(`UPDATE hash_data SET password = ? WHERE SSID = ? AND \`key\` = ?`, [password, ssid, key], (err) => {
            if (err) {
              console.error('Error updating hash data:', err);
              return res.status(500).json({ error: 'Internal server error' });
            }
            console.log(`Password updated for SSID: ${ssid}, Key: ${key}`);

            // Parse the hash and format it for the potfile
            const hashParts = hash.split('*');
            if (hashParts.length > 4) {
              const formattedHash = `${hashParts[2]}:${hashParts[3]}:${hashParts[4]}:${ssid}:${password}\n`;

              // Append to boss.potfile
              fs.appendFile(bossPotfilePath, formattedHash, (err) => {
                if (err) {
                  console.error('Error writing to boss.potfile:', err);
                }
              });

              // Append to user's potfile
              const userPotfilePath = path.join(RESULTS_DIR, `${keyData.email}.potfile`);
              fs.appendFile(userPotfilePath, formattedHash, (err) => {
                if (err) {
                  console.error('Error writing to user potfile:', err);
                }
              });
            }

            res.json({ success: true });
          });
        } else {
          console.log(`Incorrect password for SSID: ${ssid}, Key: ${key}`);
          res.json({ success: false });
        }
      });
    });
  });
});

// New endpoint to redeem a rank key
app.post('/redeem-rank', (req, res) => {
  const { userKey, rankKey } = req.body;
  if (!userKey || !rankKey) {
    return res.status(400).json({ error: 'Missing parameters.' });
  }
  if (!/^[A-Za-z0-9]{12}$/.test(rankKey)) {
    return res.status(400).json({ error: 'Invalid rank key format.' });
  }
  
  const validKeysPath = path.join(__dirname, 'rank_keys.txt');
  let keys;
  try {
    keys = fs.readFileSync(validKeysPath, 'utf-8')
      .split('\n')
      .map(line => line.trim())
      .filter(line => line);
  } catch (err) {
    console.error("Error reading rank keys file:", err);
    return res.status(500).json({ error: 'Internal server error' });
  }
  
  if (!keys.includes(rankKey)) {
    return res.status(400).json({ error: 'Invalid or already redeemed rank key.' });
  }
  
  // Remove the redeemed key from the file
  keys = keys.filter(key => key !== rankKey);
  fs.writeFileSync(validKeysPath, keys.join('\n'));
  
  const validityPeriod = 7 * 24 * 60 * 60; // 7 days in seconds
  // Get current rank info for the user
  db.query(`SELECT \`rank\`, rank_time, rank_activation FROM users WHERE \`key\` = ?`, [userKey], (err, rows) => {
    if (err) {
      console.error("Error fetching user rank info:", err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (!rows || rows.length === 0) {
      return res.status(400).json({ error: 'Invalid user key.' });
    }
    const user = rows[0];
    let newRankTime = validityPeriod;
    const now = new Date();
    if (user.rank === 'VIP' && user.rank_activation) {
      const activationTime = new Date(user.rank_activation);
      const elapsed = Math.floor((now - activationTime) / 1000); // seconds elapsed
      const remaining = Math.max(user.rank_time - elapsed, 0);
      newRankTime = remaining + validityPeriod;
    }
    db.query(`UPDATE users SET \`rank\` = 'VIP', rank_time = ?, rank_activation = NOW() WHERE \`key\` = ?`, [newRankTime, userKey], (err) => {
      if (err) {
        console.error("Error updating rank:", err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      // Log the rank activation in sent_rank_keys by updating activation_time and key column
      db.query(`UPDATE sent_rank_keys SET activation_time = NOW(), \`key\` = ? WHERE rank_key = ?`, [userKey, rankKey], (err) => {
        if (err) {
          console.error("Error logging rank activation:", err);
        }
        res.json({ success: true, message: 'Rank activated!' });
      });
    });
  });
});

// Scheduled task to reset expired ranks
setInterval(() => {
  const resetQuery = `
    UPDATE users 
    SET \`rank\` = NULL, rank_time = 0, rank_activation = NULL 
    WHERE \`rank\` IS NOT NULL 
      AND TIMESTAMPDIFF(SECOND, rank_activation, NOW()) >= rank_time
  `;
  db.query(resetQuery, (err) => {
    if (err) console.error("Error resetting expired ranks:", err);
  });
}, 60 * 1000);

// Add new endpoint to fetch user rank
app.get('/user-rank', (req, res) => {
  const userKey = req.query.key;
  if (!userKey) {
    return res.status(400).json({ error: 'No key provided' });
  }
  db.query(`SELECT \`rank\` FROM users WHERE \`key\` = ?`, [userKey], (err, rows) => {
    if (err) {
      console.error("Error fetching user rank:", err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    const rank = rows && rows.length > 0 && rows[0].rank ? rows[0].rank : 'common';
    res.json({ rank });
  });
});


// Add new endpoint to fetch user rank info including time remaining
app.get('/user-rank-info', (req, res) => {
  const userKey = req.query.key;
  if (!userKey) {
    return res.status(400).json({ error: 'No key provided' });
  }
  db.query(`SELECT \`rank\`, rank_time, rank_activation FROM users WHERE \`key\` = ?`, [userKey], (err, rows) => {
    if (err) {
      console.error("Error fetching rank info:", err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (!rows || rows.length === 0) {
      return res.json({ rank: 'common', timeRemaining: 0 });
    }
    const user = rows[0];
    let timeRemaining = 0;
    if (user.rank === 'VIP' && user.rank_activation) {
      const activationTime = new Date(user.rank_activation);
      const now = new Date();
      const elapsed = Math.floor((now - activationTime) / 1000); // seconds elapsed
      timeRemaining = user.rank_time - elapsed;
      if (timeRemaining < 0) timeRemaining = 0;
    }
    res.json({ rank: user.rank || 'common', timeRemaining });
  });
});
app.get('/user_contributions', (req, res) => {
  const userKey = req.query.key;
  if (!userKey) {
    return res.status(400).json({ error: 'Bad Request: No key provided.' });
  }

  db.query(
    `SELECT 
      SUM(processed_hashes) as total_hashes,
      SUM(session_time) as total_time,
      AVG(hashrate) as avg_hashrate
     FROM hash_rate 
     WHERE user_key = ?`,
    [userKey],
    (err, rows) => {
      if (err) {
        console.error("Error fetching user contributions:", err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.json(rows[0]);
    }
  );
});

// Add new endpoint for cracker leaderboard
app.get('/cracker_leaderboard', (req, res) => {
  const sortBy = req.query.sortBy || 'processed_hashes';
  const userKey = req.query.key;
  
  if (!userKey) {
    return res.status(400).json({ error: 'No key provided' });
  }

  // Modified query to include rank
  const query = `
    SELECT 
      u.username,
      u.rank,
      SUM(hr.processed_hashes) as processed_hashes,
      SUM(hr.session_time) as total_time,
      ROUND(AVG(hr.hashrate)) as avg_hashrate
    FROM users u
    INNER JOIN hash_rate hr ON u.key = hr.user_key
    WHERE u.username IS NOT NULL
    GROUP BY u.username, u.rank, u.key
    ORDER BY SUM(hr.session_time) DESC
  `;

  console.log('Executing query:', query); // Debug log

  db.query(query, (err, rows) => {
    if (err) {
      console.error("Error fetching cracker leaderboard data:", err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    console.log('Leaderboard data:', rows); // Debug log

    const leaderboard = rows.map(row => ({
      username: row.username,
      rank: row.rank, // Include rank for VIP styling
      processed_hashes: parseInt(row.processed_hashes) || 0,
      total_time: parseInt(row.total_time) || 0,
      avg_hashrate: parseFloat(row.avg_hashrate) || 0
    }));

    res.json(leaderboard);
  });
});

// Create a table to track sent rank keys
db.query(`CREATE TABLE IF NOT EXISTS sent_rank_keys (
  email VARCHAR(255),
  rank_key VARCHAR(255),
  sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`);

// Add new fields to sent_rank_keys table if they don't exist
db.query(`SHOW COLUMNS FROM sent_rank_keys`, (err, columns) => {
    if (err) {
        console.error("Error fetching sent_rank_keys info:", err);
        return;
    }
    const colNames = columns.map(col => col.Field);
    if (!colNames.includes('sent_date')) {
        db.query(`ALTER TABLE sent_rank_keys ADD COLUMN sent_date DATETIME DEFAULT NULL`, err => {
            if (err) console.error("Error adding sent_date:", err);
        });
    }
    if (!colNames.includes('activation_time')) {
        db.query(`ALTER TABLE sent_rank_keys ADD COLUMN activation_time DATETIME DEFAULT NULL`, err => {
            if (err) console.error("Error adding activation_time:", err);
        });
    }
    if (!colNames.includes('key')) {
        db.query(`ALTER TABLE sent_rank_keys ADD COLUMN \`key\` VARCHAR(255) DEFAULT NULL`, err => {
            if (err) console.error("Error adding key column:", err);
        });
    }
});

// Function to send rank keys to top three crackers
const sendRankKeysToTopCrackers = () => {
  const validKeysPath = path.join(__dirname, 'rank_keys.txt');
  let keys;
  try {
    keys = fs.readFileSync(validKeysPath, 'utf-8')
      .split('\n')
      .map(line => line.trim())
      .filter(line => line);
  } catch (err) {
    console.error("Error reading rank keys file:", err);
    return;
  }

  db.query(`SELECT 
      u.email,
      SUM(hr.processed_hashes) as processed_hashes
    FROM users u
    INNER JOIN hash_rate hr ON u.key = hr.user_key
    WHERE u.username IS NOT NULL
    GROUP BY u.email
    ORDER BY SUM(hr.processed_hashes) DESC
    LIMIT 3`, (err, rows) => {
    if (err) {
      console.error("Error fetching top crackers:", err);
      return;
    }

    rows.forEach((row, index) => {
      const email = row.email;
      const rankKey = keys.shift(); // Get the first available key
      if (!rankKey) {
        console.error("No more rank keys available.");
        return;
      }

      // Check if the key has been sent before
      db.query(`SELECT * FROM sent_rank_keys WHERE rank_key = ?`, [rankKey], (err, sentRows) => {
        if (err) {
          console.error("Error checking sent rank keys:", err);
          return;
        }

        if (sentRows.length) {
          console.error("Rank key already sent:", rankKey);
          return;
        }

        const subject = 'PWNcrack VIP Rank Key';
        const message = `
          Thank you for your contributions to the PWNcrack initiative!
          As a top contributor, you have earned a VIP rank key: ${rankKey}
          You can redeem this key on the site for a week of VIP status, which includes perks like a colored VIP name on the leaderboard and faster cracking priority.
          You can activate multiple keys in a row, and the time will add up.
          Best regards,
          Terminatoror
        `;
        sendEmail(email, subject, message);

        // Log the sent key in the database, populating sent_date with NOW()
        db.query(`INSERT INTO sent_rank_keys (email, rank_key, sent_date) VALUES (?, ?, NOW())`, [email, rankKey], (err) => {
          if (err) {
            console.error("Error logging sent rank key:", err);
          } else {
            console.log(`Sent rank key to ${email}: ${rankKey}`);
          }
        });
      });
    });
  });
};

// Schedule the function to run every Monday at 00:00 UTC
const scheduleRankKeyDistribution = () => {
  const now = new Date();
  const dayOfWeek = now.getUTCDay();
  const daysUntilNextMonday = (8 - dayOfWeek) % 7;
  const nextMonday = new Date(now);
  nextMonday.setUTCDate(now.getUTCDate() + daysUntilNextMonday);
  nextMonday.setUTCHours(0, 0, 0, 0);
  const timeUntilNextMonday = nextMonday - now;

  setTimeout(() => {
    sendRankKeysToTopCrackers();
    setInterval(sendRankKeysToTopCrackers, 7 * 24 * 60 * 60 * 1000); // Every week
  }, timeUntilNextMonday);
};

scheduleRankKeyDistribution();

// Helper function to calculate average hashrate with 0 for missing intervals
const calculateAverageHashrate = (rows, intervalSeconds) => {
  const totalIntervals = Math.floor(intervalSeconds / 10);
  const totalHashrate = rows.reduce((sum, row) => sum + (row.hashrate || 0), 0);
  return Math.round(totalHashrate / totalIntervals);
};

// Endpoint to get average hashrate over the last 24 hours
app.get('/avg_hashrate_24h', (req, res) => {
  db.query(
    `SELECT hashrate 
     FROM hash_rate 
     WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
    (err, rows) => {
      if (err) {
        console.error("Error fetching avg hashrate 24h:", err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      const avgHashrate24h = calculateAverageHashrate(rows, 24 * 3600);
      res.json({ avgHashrate24h });
    }
  );
});

// Endpoint to get average hashrate over the last 1 week
app.get('/avg_hashrate_1w', (req, res) => {
  db.query(
    `SELECT hashrate 
     FROM hash_rate 
     WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 WEEK)`,
    (err, rows) => {
      if (err) {
        console.error("Error fetching avg hashrate 1w:", err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      const avgHashrate1w = calculateAverageHashrate(rows, 7 * 24 * 3600);
      res.json({ avgHashrate1w });
    }
  );
});

// Endpoint to get average hashrate over the last 1 month
app.get('/avg_hashrate_1m', (req, res) => {
  db.query(
    `SELECT hashrate 
     FROM hash_rate 
     WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 MONTH)`,
    (err, rows) => {
      if (err) {
        console.error("Error fetching avg hashrate 1m:", err);
        return res.status(500).json({ error: 'Internal server error' });
      }
      const avgHashrate1m = calculateAverageHashrate(rows, 30 * 24 * 3600);
      res.json({ avgHashrate1m });
    }
  );
});