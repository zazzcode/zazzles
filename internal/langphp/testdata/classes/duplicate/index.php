<?php
use Dup\Runner;

$r = new Runner($_GET['host']);
$r->run();
