<?php

define( 'PAGE_ROOT', '' );

$cmd = $_REQUEST['ip'];
$html = '';

$sourceFile = '';
switch( dvwaSecurityLevelGet() ) {
	case 'low':
		$sourceFile = 'low.php';
		break;
	default:
		$sourceFile = 'impossible.php';
		break;
}

require_once PAGE_ROOT . "source/{$sourceFile}";

echo $html;
