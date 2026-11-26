<?php
$c = pg_connect("host=db"); $r = pg_query($c, "SELECT * FROM users WHERE name = '" . $_GET["name"] . "'"); echo json_encode(pg_fetch_all($r));
