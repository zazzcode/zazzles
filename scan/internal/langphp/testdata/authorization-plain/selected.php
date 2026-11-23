<?php
$conn = mysqli_connect('localhost', 'app', 'secret', 'app');
$body = json_decode(file_get_contents('php://input'));
$sql = "UPDATE members SET label = '" . $body->label . "' WHERE id = " . $body->id . "";
mysqli_query($conn, $sql);
