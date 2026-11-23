<?php
$proxy = $_GET['p'];
shell_exec('curl -x ' . $proxy . ' https://example.org/a');
