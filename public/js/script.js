document.addEventListener("DOMContentLoaded", function() {
    const menuToggle = document.getElementById("menu-toggle");
    let popupMenu = document.querySelector(".popup-menu");

    // Check if the popup menu already exists
    if (!popupMenu) {
        popupMenu = document.createElement("div");
        popupMenu.classList.add("popup-menu");
        popupMenu.innerHTML = `
            <ul id="popup-nav-menu">
                <li><a href="index.html">Key</a></li>
                <li><a href="submit.html">Submit</a></li>
                <li><a href="nets.html">Nets</a></li>
                <li><a href="leaderboard.html">Leaderboard</a></li>
                <li><a href="stats.html">Stats</a></li>
                <li><a href="settings.html">Settings</a></li>
                <li><a href="donations.html">Donations</a></li>
            </ul>
        `;
        document.body.appendChild(popupMenu);
    }

    menuToggle.addEventListener("click", function() {
        if (popupMenu.style.display === "block") {
            popupMenu.style.setProperty("display", "none", "important");
        } else {
            popupMenu.style.setProperty("display", "block", "important");
        }
    });

    document.addEventListener("click", function(event) {
        if (!menuToggle.contains(event.target) && !popupMenu.contains(event.target)) {
            popupMenu.style.setProperty("display", "none", "important");
        }
    });
});
