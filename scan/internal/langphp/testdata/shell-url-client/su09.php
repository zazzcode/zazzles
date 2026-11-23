<?php
$tool = getenv('FETCH_TOOL');
$url = $_GET['u'];
shell_exec($tool . ' ' . $url);
