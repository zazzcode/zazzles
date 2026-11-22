<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Comment
{
    #[ORM\Column]
    private ?string $text = null;

    #[ORM\Column]
    private ?string $author = null;

    public function setText(string $text): void
    {
        $this->text = $text;
    }

    public function setAuthor(Account $author): void
    {
        $this->author = $author;
    }
}
