<?php

$GLOBALS["___mysqli_ston"] = mysqli_connect('localhost', 'dvwa', 'pw');
$message = $_POST['message'];
$name = $_POST['name'];
$query = "INSERT INTO guestbook (comment, name) VALUES ('$message','$name');";
mysqli_query($GLOBALS["___mysqli_ston"], $query);
$rows = mysqli_query($GLOBALS["___mysqli_ston"], 'SELECT name, comment FROM guestbook;');
while( $row = mysqli_fetch_assoc( $rows ) ) {
	echo "<div id=\"guestbook_comments\">Name: {$row['name']}<br />Message: {$row['comment']}<br /></div>";
}

