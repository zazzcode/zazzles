<?php
$c = new PDO("mysql:host=db","u","p"); $r = $c->query("SELECT * FROM users WHERE name = '" . $_GET["name"] . "'"); echo json_encode($r->fetchAll());
