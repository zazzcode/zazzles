<?php
namespace App; $c = new \PDO("oci:dbname=db","u","p"); $s = $c->prepare("SELECT * FROM users WHERE name = :n"); $s->bindValue(":n", $_GET["name"]); $s->execute(); echo json_encode($s->fetchAll());
