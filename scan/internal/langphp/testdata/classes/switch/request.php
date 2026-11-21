<?php
use Sw\Health;

// The command comes from the request: every case is reachable.
$chosen = new Health($_GET['command']);
$chosen->process();
