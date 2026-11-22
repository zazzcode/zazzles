<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Post
{
    #[ORM\Column]
    private ?string $title = null;

    public function getTitle(): ?string
    {
        return $this->title;
    }
}
