<?php
$h = $_GET['h'];
shell_exec('curl -H ' . $h . ' https://example.org/a');
