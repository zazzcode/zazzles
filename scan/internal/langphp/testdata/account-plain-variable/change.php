<?php
require 'db.php';
$fresh = $_POST['fresh'];
$fresh = md5($fresh);
$sql = "UPDATE `members` SET pass = '$fresh' WHERE mail = '" . $_SESSION['mail'] . "';";
mysqli_query($db, $sql);
echo 'Changed';
