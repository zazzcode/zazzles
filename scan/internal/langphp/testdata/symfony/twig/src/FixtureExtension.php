<?php
namespace App;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;
class FixtureExtension extends AbstractExtension {
    public function getFunctions() {
        return [new TwigFunction('shout', [$this, 'say'], ['is_safe' => ['html']]),
                new TwigFunction('plain', [$this, 'say'])];
    }
    public function say($value) { return $value; }
}
