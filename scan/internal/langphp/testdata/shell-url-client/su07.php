<?php
$id = $_GET['id'];
shell_exec('curl https://api.example.org/items/' . $id);
