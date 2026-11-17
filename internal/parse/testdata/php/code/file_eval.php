<?php

if (array_key_exists ("id", $_GET)) {
	$id = $_GET[ 'id' ];

	if ($id == 'en') {
		eval( '?>' . file_get_contents( "vulnerabilities/{$id}/help/help.php" ) . '<?php ' );
	} else {
		eval( '?>' . file_get_contents( "vulnerabilities/{$id}/help/help.{$id}.php" ) . '<?php ' );
	}
	$help = ob_get_contents();
}
