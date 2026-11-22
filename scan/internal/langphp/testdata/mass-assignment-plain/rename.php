<?php
require __DIR__ . '/lib/Profile.php';

$profile = new Profile();
$profile->name = $_POST['name'];
