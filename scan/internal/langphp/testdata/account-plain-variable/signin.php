<?php
require 'db.php';
$mail = $_POST['mail'];
$pass = md5($_POST['pass']);
$sql = ("SELECT name FROM settings WHERE name = 'open' LIMIT 1");
$open = mysqli_query($db, $sql);
$sql = "SELECT * FROM `members` WHERE mail = '$mail' AND pass = '$pass';";
$sql = mysqli_query($db, $sql);
if ($sql && mysqli_num_rows($sql) == 1) {
    echo 'Welcome';
    exit;
}
echo 'Try again';
