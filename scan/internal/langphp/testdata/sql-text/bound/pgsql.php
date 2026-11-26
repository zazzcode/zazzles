<?php
$c = pg_connect("host=db"); $r = pg_query_params($c, "SELECT * FROM users WHERE name = $1", array($_GET["name"])); echo json_encode(pg_fetch_all($r));
