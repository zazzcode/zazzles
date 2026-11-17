<?php

$target = $_REQUEST['ip'];
$cmd = shell_exec( 'ping  -c 4 ' . $target );
$html = "<pre>{$cmd}</pre>";
echo $html;

