<?php

use Symfony\Component\Yaml\Yaml;
Yaml::parse($_POST['y'], Yaml::PARSE_OBJECT); // PHP-08
