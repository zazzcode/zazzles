<?php
require 'db.php';
$mail = $_POST['mail'];
$pass = md5($_POST['pass']);
mysqli_query($db, "INSERT INTO members (mail, pass) VALUES ('$mail', '$pass')");
echo 'Registered';
