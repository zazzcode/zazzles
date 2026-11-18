<?php

$link = mysqli_connect('localhost', 'app', 'pw');
$id = $_GET['id'];
$result = mysqli_query($link, "SELECT name FROM users WHERE id = '" . $id . "'");
while ( $row = mysqli_fetch_assoc( $result ) ) {
	echo htmlspecialchars( $row['name'] );
}
