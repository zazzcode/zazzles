<?php

const KEY = 'fixture-key';
$d = $_COOKIE['p'];
$sig = $_GET['signature'];
if (!hash_equals(hash_hmac('sha256', $d, KEY), $sig)) {
    exit;
}
unserialize($d); // PHP-C2
