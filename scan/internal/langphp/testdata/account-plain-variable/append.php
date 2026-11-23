<?php
require 'db.php';
$mail = $_POST['mail'];
$sql = "SELECT id FROM `members`";
$sql .= " WHERE mail = '$mail'";
$res = mysqli_query($db, $sql);
if (mysqli_num_rows($res) > 0) {
    echo 'Known';
    exit;
}
echo 'Unknown';
