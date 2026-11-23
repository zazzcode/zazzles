<?php
require 'db.php';
$mail = $_POST['mail'];
if (isset($_POST['product'])) {
    $sql = "SELECT id FROM products WHERE name = 'open'";
} else {
    $sql = "SELECT id FROM `members` WHERE mail = '$mail'";
}
$res = mysqli_query($db, $sql);
if (mysqli_num_rows($res) > 0) {
    echo 'Known';
    exit;
}
echo 'Unknown';
