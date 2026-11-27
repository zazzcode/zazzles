<?php
$c = sqlsrv_connect("db"); $id = str_replace("'", "''", $_GET["id"]);
$r = sqlsrv_query($c, "SELECT name FROM users WHERE id = '" . $id . "'");
echo json_encode(sqlsrv_fetch_array($r));
