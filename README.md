```markdown
# Backend Project 🚀

## Advantages

- **Distributed Hash Cracking:** Leverages modern hash cracking methods with full support for hc22000.
- **Real-Time Discord Integration:** Get instant notifications via Discord to keep you informed.
- **Reward System:** Earn rewards by running help_crack jobs that power community contributions.
- **Custom Themes & Plugins:** Enjoy a personalized experience with customizable themes and Pwnagotchi plugins.
- **Efficient Hash Management:** Automatically remove duplicates and easily manage your hash data.
- **Seamless Integration:** Easy-to-configure MySQL and SMTP (Nodemailer) support for smooth backend operation.
- **Inspired by Innovation:** Built on ideas from Pwnagotchi and integrated with industry-standard tools like Hashcat and hcxpcapng Tools.

---

## Features
- ⚡ Fast and scalable backend  
- 🔒 Secure user authentication  
- 🛠️ Easy-to-configure MySQL integration  
- 🔧 Simple setup via npm  

---

## Setup

### 1. Install Dependencies
Run the following command in your project directory:
```bash
npm install
```

### 2. Configure MySQL
Make sure you have MySQL installed and running. Create a database for the project and update the credentials in `server.js`.

### 3. Update Credentials in server.js
Open `server.js` and replace the dummy credentials with your actual MySQL configurations.  
Make the following changes:
```javascript
// in server.js (line 44-49)
// ...existing code...
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'MYSQL_PASSWORD_PLACEHOLDER',  // [Line 47] Replace with your MySQL password
  database: 'pwncrack'
});
// ...existing code...
```

### 4. Configure Nodemailer
Set up your SMTP settings for sending emails. In `server.js`, update the Nodemailer configuration as follows:
```javascript
// in server.js (line 380-386)
// ...existing code...
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'EMAIL_ADDRESS_PLACEHOLDER',    // [Line 382] Replace with your SMTP user/email
    pass: 'EMAIL_PASSWORD_PLACEHOLDER'      // [Line 383] Replace with your SMTP password
  },
  tls: {
    rejectUnauthorized: false
  }
});
// ...existing code...
```

### 5. Start the Server
After completing the setup, start the backend server:
```bash
npm run start
```

---

## License
This project is open for contribution and exploration. You are free to view, contribute to, and modify the codebase. However, **commercial or private use, distribution, or marketing of this code is strictly prohibited without explicit permission.** By using or contributing to this project, you agree to these terms.

---

## Acknowledgements
- **[Hashcat](https://hashcat.net/hashcat/):** For pioneering high-performance password cracking.
- **[hcxpcapng Tools](https://github.com/ZerBea/hcxtools):** For providing essential tools in hash conversion.
- **[Pwnagotchi](https://pwnagotchi.org/):** For inspiring a new wave of innovation in distributed network security.
- **[AngryOxide](https://github.com/AngryOxide):** For their invaluable contributions and insights into the cybersecurity community.

---

Happy coding and secure cracking! 😎🔓
```