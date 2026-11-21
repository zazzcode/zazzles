<?php

class Logger { function __destruct() {} }
class Token { function __unserialize(array $data): void {} }
class Plain {}
unserialize($_COOKIE['p']); // PHP-E1
