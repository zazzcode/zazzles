<?php

$page = $_GET['page'];
$allowed = ['include.php', 'file1.php', 'file2.php', 'file3.php'];
if( !in_array($page, $allowed) ) {
    echo "ERROR: File not found!";
    exit;
}
include( $page );

$raw = $_GET['raw'];
include( $raw );
