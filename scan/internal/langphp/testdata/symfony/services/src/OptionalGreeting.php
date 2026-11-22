<?php
namespace App;

use Symfony\Component\HttpFoundation\Response;

class OptionalGreeting
{
    public function __construct(private bool $enabled) {}

    public function render(string $text) {
        if ($this->enabled) {
            return new Response('<p>' . $text . '</p>');
        }
    }
}
