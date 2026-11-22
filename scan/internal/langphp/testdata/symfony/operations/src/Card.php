<?php
namespace App;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Card {
    #[ORM\Column]
    private string $text;

    public function setText(string $text) { $this->text = $text; }
    public function getText() { return $this->text; }
}
