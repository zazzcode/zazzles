<?php
$c = new PDO("mysql:host=db","u","p"); $s = $c->prepare("SELECT * FROM users WHERE name = ?"); $s->execute([$_GET["name"]]); echo json_encode($s->fetchAll());
