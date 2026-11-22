<?php
use App\Kernel;
require dirname(__DIR__).'/vendor/autoload.php';
(new Kernel('test', false))->handle(Request::createFromGlobals());
