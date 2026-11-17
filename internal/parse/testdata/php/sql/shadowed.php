<?php

function mysqli_query( $link, $query ) { return array(); }
$id = $_REQUEST['id'];
$result = mysqli_query($GLOBALS["___mysqli_ston"], "SELECT * FROM users WHERE user_id = '$id'");

