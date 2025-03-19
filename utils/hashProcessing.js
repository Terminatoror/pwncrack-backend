const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql');

/**
 * Extract hashes from a 22000 file using hcxhashtool with --essid-group.
 * It creates multiple output files (one per ESSID) in a temporary directory,
 * then gathers the first line (the hash) from each file and writes (or appends)
 * them to user-specific files in the handshakes directory (named as <key>-<index>.hc22000).
 * If that file already exists, it is skipped to avoid duplicates.
 *
 * @param {string} filePath - Path to the input 22000 file.
 * @param {string} key - User key, used to name the handshake files.
 * @param {Array<string>} filenames - Array of filenames to use for the handshake files.
 * @returns {Promise<string[]>} - A promise that resolves to an array of hashes.
 */
function extractHashesFromHC22000(filePath, key, filenames) {
  return new Promise((resolve, reject) => {
    if (!key) {
      return reject('Key is undefined');
    }

    // Create a unique temporary directory for the user
    const tempDirBase = path.join(__dirname, '..', 'tmp');
    if (!fs.existsSync(tempDirBase)) {
      fs.mkdirSync(tempDirBase, { recursive: true });
    }

    fs.mkdtemp(path.join(tempDirBase, `${key}-hcxhash-`), (err, tempDir) => {
      if (err) {
        return reject(`Error creating temporary directory: ${err.message}`);
      }

      // Run hcxhashtool with --essid-group.
      // Set the working directory to tempDir so that output files are created there.
      exec(`hcxhashtool -i ${filePath} --essid-group`, { cwd: tempDir }, (error, stdout, stderr) => {
        if (error) {
          console.error(`Error extracting hashes: ${stderr}`);
          return reject(`Error extracting hashes: ${stderr}`);
        }

        // Log stdout for debugging
        console.log(`hcxhashtool output: ${stdout}`);

        // Read the temporary directory for all files ending with ".22000"
        fs.readdir(tempDir, (err, files) => {
          if (err) {
            return reject(`Error reading output directory: ${err.message}`);
          }
          // Filter for files ending with ".22000"
          const hashFiles = files.filter(file => file.endsWith('.22000'));
          // Map each file to its first line (the hash)
          const hashes = hashFiles.map(file => {
            const fileContent = fs.readFileSync(path.join(tempDir, file), 'utf8');
            return fileContent.split('\n')[0].trim();
          });

          // Log the hashes and filenames for debugging
          console.log(`Extracted hashes: ${hashes}`);
          console.log(`Generated filenames: ${filenames}`);

          // Ensure filenames array matches the length of hashes array
          if (filenames.length < hashes.length) {
            for (let i = filenames.length; i < hashes.length; i++) {
              filenames.push(`${generateRandomFileName(12)}.hc22000`);
            }
          }

          // Set the handshake directory to the parent directory of the current script
          const handshakeDir = path.join(__dirname, '..', 'handshakes');
          if (!fs.existsSync(handshakeDir)) {
            fs.mkdirSync(handshakeDir, { recursive: true });
          }

          // Initialize MySQL connection
          const connection = mysql.createConnection({
            host: 'localhost',
            user: 'root',
            password: 'YOUR-MYSQL-PASSWORD',
            database: 'pwncrack'
          });

          connection.connect();

          // Ensure the users table has the necessary columns
          connection.query(`SHOW COLUMNS FROM users`, (err, columns) => {
            if (err) {
              return reject(`Error fetching columns: ${err.message}`);
            }
            const columnNames = columns.map(column => column.Field);
            if (!columnNames.includes('BSSID_display')) {
              connection.query(`ALTER TABLE users ADD COLUMN \`BSSID_display\` VARCHAR(255) DEFAULT 'false'`, (err) => {
                if (err) {
                  console.error("Error adding BSSID_display column:", err);
                }
              });
            }

            // Get the latest index for the user key
            connection.query(`SELECT MAX(CAST(SUBSTRING_INDEX(SUBSTRING_INDEX(file_name, '-', -1), '.', 1) AS UNSIGNED)) AS maxIndex FROM hash_data WHERE \`key\` = ?`, [key], (err, results) => {
              if (err) {
                return reject(`Error fetching max index: ${err.message}`);
              }

              let startIndex = results[0].maxIndex ? results[0].maxIndex + 1 : 1;

              // Write each hash to a separate file with the provided filenames
              hashes.forEach((hash, index) => {
                const userFile = path.join(handshakeDir, filenames[index]);
                if (!fs.existsSync(userFile)) {
                  fs.writeFileSync(userFile, hash, 'utf8');
                }
              });

              // Log the hashes written to files for debugging
              console.log(`Hashes written to files: ${hashes}`);

              // Delete the temporary directory
              fs.rm(tempDir, { recursive: true, force: true }, (err) => {
                if (err) {
                  console.error(`Error deleting temporary directory: ${err.message}`);
                }
              });

              // Delete the initially uploaded file
              fs.unlink(filePath, (err) => {
                if (err) {
                  console.error(`Error deleting uploaded file: ${err.message}`);
                }
              });

              connection.end();
              resolve(hashes);
            });
          });
        });
      });
    });
  });
}

// Function to generate random file name
const generateRandomFileName = (length) => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
};

module.exports = { extractHashesFromHC22000, generateRandomFileName };
