<?php

$d = $_COOKIE['p'];
$sum = $_GET['digest'];
if (md5($d) === $sum) {
    unserialize($d); // PHP-C3
}
