<?php

function preferences($opts) {
    unserialize($_GET['d'], $opts); // PHP-06
}
preferences($_GET['opts']);
