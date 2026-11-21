<?php

use Symfony\Component\Yaml\Yaml as ConfigYaml;
ConfigYaml::parse($_POST['y'], flags: ConfigYaml::PARSE_OBJECT | ConfigYaml::PARSE_EXCEPTION_ON_INVALID_TYPE); // PHP-09
