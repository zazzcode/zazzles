<?php
$c = mysqli_connect("db","u","p","a"); $r = mysqli_query($c, "SELECT * FROM users WHERE name = '" . $_GET["name"] . "'"); echo json_encode(mysqli_fetch_all($r));
