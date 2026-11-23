<?php
$url = $_GET['u'];
shell_exec('curl -s ' . escapeshellarg($url));
