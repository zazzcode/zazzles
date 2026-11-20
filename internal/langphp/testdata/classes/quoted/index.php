<?php
use Quote\Pinger;

$p = new Pinger($_GET['host']);
$p->ping();
