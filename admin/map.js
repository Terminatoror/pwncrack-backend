document.addEventListener('DOMContentLoaded', function() {
    var map = L.map('map').setView([0, 0], 2);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);

    var markers = L.markerClusterGroup();

    fetch('/locations')
        .then(response => {
            if (!response.ok) {
                throw new Error(`Network response was not ok: ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            if (!Array.isArray(data)) {
                throw new Error('Data is not an array');
            }

            data.forEach(location => {
                const { latitude, longitude, SSID, password } = location;

                // Check if latitude and longitude are valid numbers
                if (typeof latitude === 'number' && typeof longitude === 'number') {
                    var marker = L.marker([latitude, longitude]);
                    var popupContent = `<strong>SSID:</strong> ${SSID}<br><strong>Password:</strong> ${password}`;
                    marker.bindPopup(popupContent);
                    markers.addLayer(marker);
                } else {
                    console.warn('Invalid location data:', location);
                }
            });

            map.addLayer(markers);

            // Check if there are any valid markers before fitting bounds
            if (markers.getLayers().length > 0) {
                map.fitBounds(markers.getBounds());
            } else {
                console.warn('No valid markers to display.');
            }
        })
        .catch(error => console.error('Error fetching location data:', error));
});
