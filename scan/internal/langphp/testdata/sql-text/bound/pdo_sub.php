<?php
class Db extends PDO {} $c = new Db("sqlsrv:Server=db","u","p"); $s = $c->prepare("SELECT * FROM users WHERE name = ?"); $s->execute([$_GET["name"]]); echo json_encode($s->fetchAll());
