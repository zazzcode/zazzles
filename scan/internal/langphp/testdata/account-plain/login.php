<?php
require 'db.php';
$mail = $_POST['mail'];
$res = mysqli_query($db, "SELECT id FROM members WHERE mail = '$mail' AND pass = '" . md5($_POST['pass']) . "'");
if (mysqli_num_rows($res) > 0) {
    echo 'Welcome';
    exit;
}
echo 'Try again';
