<?php

unserialize($_POST['d'], ['allowed_classes' => [Prefs::class, 'Theme']]); // PHP-C4
