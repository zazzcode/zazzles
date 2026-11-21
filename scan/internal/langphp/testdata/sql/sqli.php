<?php

$GLOBALS["___mysqli_ston"] = mysqli_connect('localhost', 'dvwa', 'pw');
$id = $_REQUEST['id'];
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
while( $row = mysqli_fetch_assoc( $result ) ) {
	$html .= "<pre>ID: {$id} First name: {$row['first_name']}</pre>";
}
echo $html;
