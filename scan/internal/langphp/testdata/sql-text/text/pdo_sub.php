<?php
class Db extends PDO {} $c = new Db("sqlsrv:Server=db","u","p"); $r = $c->query("SELECT * FROM users WHERE name = '" . $_GET["name"] . "'"); echo json_encode($r->fetchAll());
