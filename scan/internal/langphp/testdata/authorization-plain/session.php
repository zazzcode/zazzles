<?php
if (!$_SESSION['uid']) {
    exit;
}
if ($_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
    exit;
}
$conn = mysqli_connect('localhost', 'app', 'secret', 'app');
mysqli_query($conn, "UPDATE members SET label = 'a' WHERE id = 1");
