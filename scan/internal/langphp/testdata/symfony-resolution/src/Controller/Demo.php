<?php
namespace App\Controller;

class Demo {
    public function __invoke() { return 'demo'; }
    public function show($id) { return $id; }
}
