<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Note
{
    #[ORM\Column]
    private ?string $body = null;

    public function setBody(string $body): void
    {
        $this->body = $body;
    }
}
