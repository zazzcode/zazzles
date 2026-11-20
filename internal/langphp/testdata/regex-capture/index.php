<?php
// The capture admits any character after "img:http", including shell syntax.
$source = $_GET['source'];
if (preg_match('/^img:(http.*)$/', $source, $image)) {
	shell_exec('identify ' . $image[1]);
}

// The capture admits only a host alphabet; its adequacy is the model's call.
$target = $_GET['target'];
if (preg_match('/^host:([a-z0-9.-]+)$/', $target, $host)) {
	shell_exec('ping -c 1 ' . $host[1]);
}

// Quoting after the capture is another control and keeps the path guarded.
$quoted = $_GET['quoted'];
if (preg_match('/^img:(http.*)$/', $quoted, $parts)) {
	shell_exec('identify ' . escapeshellarg($parts[1]));
}
