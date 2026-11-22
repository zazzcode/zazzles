<?php
namespace App;
use Doctrine\ORM\Mapping as ORM;
#[ORM\Entity]
class Label {
    #[ORM\Column]
    private string $caption;
    public function setCaption(string $caption) { $this->caption = $caption; }
    public function getCaption() { return $this->caption; }
}
