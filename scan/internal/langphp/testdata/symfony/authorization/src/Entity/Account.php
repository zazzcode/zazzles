<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
class Account implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Column]
    private ?string $grants = null;

    #[ORM\Column]
    private ?string $mail = null;

    #[ORM\Column]
    private ?string $resetCode = null;

    public function setGrants(string $grants): void
    {
        $this->grants = $grants;
    }

    public function getMail(): ?string
    {
        return $this->mail;
    }

    public function getResetCode(): ?string
    {
        return $this->resetCode;
    }

    public function getUserIdentifier(): string
    {
        return (string) $this->mail;
    }

    public function getRoles(): array
    {
        return [$this->grants];
    }

    public function getPassword(): ?string
    {
        return null;
    }

    public function eraseCredentials(): void
    {
    }
}
