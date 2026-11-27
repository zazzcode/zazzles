<?php
$c = oci_connect("u","p","db"); $id = str_replace("'", "''", $_POST["id"]);
$r = oci_parse($c, "SELECT name FROM users WHERE id = '" . $id . "'");
oci_execute($r); echo "ok";
