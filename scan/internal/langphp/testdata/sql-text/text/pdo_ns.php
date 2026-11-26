<?php
namespace App; $c = new \PDO("oci:dbname=db","u","p"); $r = $c->query("SELECT * FROM users WHERE name = '" . $_GET["name"] . "'"); echo json_encode($r->fetchAll());
