<?php

$db = new PDO('sqlite:/tmp/db.sqlite');
$id = $_GET['id'];
if( is_numeric( $id ) ) {
	$id = intval( $id );
	$stmt = $db->prepare( 'SELECT first_name FROM users WHERE user_id = :id LIMIT 1;' );
	$stmt->bindParam( ':id', $id, PDO::PARAM_INT );
	$stmt->execute();
	$row = $stmt->fetch();
	echo "<pre>{$row['first_name']}</pre>";
}

