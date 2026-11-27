<?php
$db = new SQLite3("a.db"); $id = SQLite3::escapeString($_GET["id"]);
$r = $db->query("SELECT name FROM users WHERE id = '" . $id . "'");
echo json_encode($r->fetchArray());
