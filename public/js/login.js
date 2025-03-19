document.addEventListener("DOMContentLoaded", function () {
  const loginButton = document.getElementById("login-button");
  const logoutButton = document.getElementById("logout-button");
  const loggedInElement = document.getElementById("loggedIn");
  const loginKeyInput = document.getElementById("login-key");

  // Check if there's a saved key in localStorage on page load
  const savedKey = localStorage.getItem("userKey");
  if (savedKey) {
    setLoggedInState(savedKey);
  }

  // Handle the login button click
  loginButton.addEventListener("click", function () {
    const enteredKey = loginKeyInput.value.trim();
    if (enteredKey) {
      // Send a POST request to check if the entered key is valid
      fetch('/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ key: enteredKey })
      })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          localStorage.setItem("userKey", enteredKey); // Save the key in localStorage
          setLoggedInState(enteredKey);
          location.reload(); // Auto-refresh after login
        } else {
          alert('Invalid key');
        }
      })
      .catch(err => {
        console.error('Login error:', err);
      });
    }
  });

  // Handle the logout button click
  logoutButton.addEventListener("click", function () {
    localStorage.removeItem("userKey"); // Remove the key from localStorage
    setLoggedOutState();
    location.reload(); // Auto-refresh after logout
  });

  // Function to set logged in state
  function setLoggedInState(key) {
    loggedInElement.innerText = `Key: ${key}`;
    loggedInElement.setAttribute('data-loggedin', 'true');
    loginButton.style.display = 'none';
    logoutButton.style.display = 'inline';
    loginKeyInput.style.display = 'none';
  }

  // Function to set logged out state
  function setLoggedOutState() {
    loggedInElement.innerText = 'Key: Not Logged In';
    loggedInElement.setAttribute('data-loggedin', 'false');
    loginButton.style.display = 'inline';
    logoutButton.style.display = 'none';
    loginKeyInput.style.display = 'inline';
  }
});
