<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
class Member implements UserInterface
{
    #[ORM\Column]
    private ?string $label = null;

    #[ORM\Column]
    private ?string $grants = null;

    public function setLabel(string $label): void
    {
        $this->label = $label;
    }

    public function setGrants(string $grants): void
    {
        $this->grants = $grants;
    }

    public function getOwner(): ?Member
    {
        return null;
    }

    public function getId(): ?string
    {
        return null;
    }

    public function getUserIdentifier(): string
    {
        return '';
    }

    public function getRoles(): array
    {
        return [$this->grants];
    }

    public function eraseCredentials(): void
    {
    }
}
