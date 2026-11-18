<?php

$GLOBALS["___mysqli_ston"] = mysqli_connect('localhost', 'dvwa', 'pw');
if( isset( $_POST[ 'btnSign' ] ) ) {
	$message = trim( $_POST[ 'message' ] );
	$name    = trim( $_POST[ 'name' ] );
	$message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
	$query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
}

$guestbook = '';
$query  = "SELECT name, comment FROM guestbook";
$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query );
while( $row = mysqli_fetch_row( $result ) ) {
	$name    = $row[0];
	$comment = $row[1];
	$guestbook .= "<div id=\"guestbook_comments\">Name: {$name}<br />" . "Message: {$comment}<br /></div>\n";
}
echo $guestbook;
