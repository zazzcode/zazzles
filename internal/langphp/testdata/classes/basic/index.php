<?php
use Basic\C;

$seg = $_GET['command'];
$c = new C($_SERVER['REQUEST_METHOD'], $seg);
$c->run();
