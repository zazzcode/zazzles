<?php

class Store { function unserialize($value) { return $value; } }
$store = new Store();
$store->unserialize($_GET['d']); // PHP-N6
