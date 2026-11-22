<?php
namespace App;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'post')]
class Post
{
    #[ORM\Column]
    private string $title;
    public function getTitle(): string { return $this->title; }
}
