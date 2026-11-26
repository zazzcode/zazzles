<?php
$c = mysqli_connect("db","u","p","a"); $s = mysqli_prepare($c, "SELECT * FROM users WHERE name = ?"); $n = $_GET["name"]; mysqli_stmt_bind_param($s, "s", $n); mysqli_stmt_execute($s); echo json_encode(mysqli_fetch_all(mysqli_stmt_get_result($s)));
