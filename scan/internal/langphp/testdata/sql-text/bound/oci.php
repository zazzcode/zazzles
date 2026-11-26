<?php
$c = oci_connect("u","p","db"); $s = oci_parse($c, "SELECT * FROM users WHERE name = :n"); oci_bind_by_name($s, ":n", $_GET["name"]); oci_execute($s); echo json_encode(oci_fetch_all($s, $rows));
