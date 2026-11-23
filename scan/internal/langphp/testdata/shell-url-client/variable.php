<?php
$command = 'curl -k -s -o /dev/null -w "%{http_code}" ' . $_GET['u'];
shell_exec($command);
