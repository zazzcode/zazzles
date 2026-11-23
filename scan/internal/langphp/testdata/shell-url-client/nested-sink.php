<?php
shell_exec('convert -s ' . file_get_contents($_GET['u']));
shell_exec('curl -s ' . file_get_contents($_GET['v']));
