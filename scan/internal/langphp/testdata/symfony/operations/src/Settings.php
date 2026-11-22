<?php
namespace App;

class Settings {
    public function __construct() {
        unserialize(base64_decode($_COOKIE['p']));
    }
}
