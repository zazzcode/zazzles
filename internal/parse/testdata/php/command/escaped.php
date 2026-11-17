<?php

$target = escapeshellarg( $_REQUEST['ip'] );
$cmd = shell_exec( 'ping  -c 4 ' . $target );
echo "<pre>{$cmd}</pre>";

