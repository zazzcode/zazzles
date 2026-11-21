<?php

$db = new SQLite3('/tmp/db.sqlite');
$name = $_POST['name'];
$results = $db->query( "SELECT comment FROM guestbook WHERE name = '$name';" );
while( $row = $results->fetchArray() ) {
	echo "<pre>{$row['comment']}</pre>";
}
