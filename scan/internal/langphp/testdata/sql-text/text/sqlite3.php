<?php
$c = new SQLite3("a.db"); $r = $c->query("SELECT * FROM users WHERE name = '" . $_GET["name"] . "'"); echo json_encode($r->fetchArray());
