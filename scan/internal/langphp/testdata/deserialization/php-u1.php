<?php

use Symfony\Component\Yaml\Yaml;
$flags = $_GET['flags'];
Yaml::parse($_POST['y'], $flags); // PHP-U1
