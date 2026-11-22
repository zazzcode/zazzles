<?php
namespace App;

use Twig\Environment;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class CardExtension extends AbstractExtension {
    public function getFunctions() {
        return [new TwigFunction('card_preview', [$this, 'preview'], ['needs_environment' => true])];
    }

    public function preview(Environment $env, string $source) {
        return $env->createTemplate($source)->render();
    }
}
