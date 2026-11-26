<?php
$c = sqlsrv_connect("db"); $r = sqlsrv_query($c, "SELECT * FROM users WHERE name = ?", array($_GET["name"])); echo json_encode(sqlsrv_fetch_array($r));
