<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Item
{
    #[ORM\Column]
    private ?string $name = null;

    #[ORM\Column]
    private ?string $file = null;

    #[ORM\Column]
    private ?bool $archived = null;

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getFile(): ?string
    {
        return $this->file;
    }

    public function getOwner(): ?Account
    {
        return null;
    }

    public function setArchived(bool $archived): void
    {
        $this->archived = $archived;
    }
}
