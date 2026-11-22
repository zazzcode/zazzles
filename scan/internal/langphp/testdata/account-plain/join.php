<?php
require 'db.php';
$mail = $_POST['mail'];
$res = mysqli_query($db, "SELECT id FROM members WHERE mail = '$mail'");
if (mysqli_num_rows($res) > 0) {
    echo 'That address has an account';
    exit;
}
echo 'Choose a password';
