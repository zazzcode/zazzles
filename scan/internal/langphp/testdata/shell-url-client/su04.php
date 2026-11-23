<?php
$name = $_GET['n'];
shell_exec('curl -s -o ' . $name . ' https://example.org/a');
