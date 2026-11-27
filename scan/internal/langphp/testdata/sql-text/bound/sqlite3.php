<?php
$c = new SQLite3("a.db"); $s = $c->prepare("SELECT * FROM users WHERE name = :n"); $s->bindValue(":n", $_GET["name"]); $r = $s->execute(); echo json_encode($r->fetchArray());
