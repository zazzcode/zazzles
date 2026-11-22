<?php
namespace App;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'user')]
class User
{
    #[ORM\Column]
    private string $name;
    public function getName(): string { return $this->name; }
}
