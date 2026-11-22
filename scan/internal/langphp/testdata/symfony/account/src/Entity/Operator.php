<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
class Operator implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Column]
    private ?string $login = null;

    #[ORM\Column]
    private ?string $passwordDigest = null;

    public function setPasswordDigest(string $digest): void
    {
        $this->passwordDigest = $digest;
    }

    public function getUserIdentifier(): string
    {
        return (string) $this->login;
    }

    public function getRoles(): array
    {
        return ['ROLE_STAFF'];
    }

    public function getPassword(): ?string
    {
        return $this->passwordDigest;
    }

    public function eraseCredentials(): void
    {
    }
}
