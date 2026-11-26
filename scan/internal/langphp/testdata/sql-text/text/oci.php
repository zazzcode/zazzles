<?php
$c = oci_connect("u","p","db"); $s = oci_parse($c, "SELECT * FROM users WHERE name = '" . $_GET["name"] . "'"); oci_execute($s); echo json_encode(oci_fetch_all($s, $rows));
