<?php
function first($value) { return second($value); }
function second($value) { return third($value); }
function third($value) { return fourth($value); }
function fourth($value) { return fifth($value); }
function fifth($value) {
    $quoted = escapeshellarg($value);
    system('printf ' . $quoted);
    return htmlspecialchars($value);
}
