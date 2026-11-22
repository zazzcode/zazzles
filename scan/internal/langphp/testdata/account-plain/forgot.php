<?php
require 'db.php';
$mail = $_POST['mail'];
$res = mysqli_query($db, "SELECT id FROM members WHERE mail = '$mail'");
if (mysqli_num_rows($res) > 0) {
    $token = bin2hex(random_bytes(16));
    mysqli_query($db, "UPDATE members SET token = '$token' WHERE mail = '$mail'");
    mail($mail, 'Reset', 'Your code: ' . $token);
}
echo 'If the address is known, a message is on its way';
