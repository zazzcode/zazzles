<?php
$file = $_GET['f'];
shell_exec('convert ' . $file . ' out.png');
