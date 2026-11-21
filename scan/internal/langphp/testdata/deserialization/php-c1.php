<?php

const KEY = 'fixture-key';
$d = $_COOKIE['p'];
$sig = $_GET['signature'];
if (hash_equals(hash_hmac('sha256', $d, KEY), $sig)) {
    unserialize($d); // PHP-C1
}
