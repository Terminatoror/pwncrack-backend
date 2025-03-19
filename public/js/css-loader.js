document.addEventListener('DOMContentLoaded', function() {
  const userKey = localStorage.getItem('userKey');
  if (userKey) {
    const themeStylesheet = document.getElementById('theme-stylesheet');
    themeStylesheet.href = `/user-theme.css?key=${userKey}`;
    themeStylesheet.rel = 'stylesheet'; // Change rel to stylesheet after loading
    themeStylesheet.onload = () => {
      document.body.style.display = 'block'; // Show the body once the CSS is loaded
    };
  } else {
    document.body.style.display = 'block'; // Show the body if no user key is found
  }
});
