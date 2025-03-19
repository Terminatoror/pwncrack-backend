<?php
$servername = "localhost";
$username = "root";
$password = "YOUR-MYSQL-PASSWORD";  // Replace with your MySQL password
$dbname = "pwncrack";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$sql = "SELECT lat AS latitude, longitude FROM hash_data";
$result = $conn->query($sql);

$locations = array();
if ($result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
        $locations[] = $row;
    }
}

$conn->close();

header('Content-Type: application/json');
echo json_encode($locations);
?>
