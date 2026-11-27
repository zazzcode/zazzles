<?php
$c = pg_connect("dbname=a"); $id = pg_escape_string($c, $_GET["id"]);
$r = pg_query($c, "SELECT name FROM users WHERE id = " . $id);
echo json_encode(pg_fetch_all($r));
