<?php
namespace App\Model;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
class Member implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Column]
    private ?string $handle = null;

    #[ORM\Column]
    private ?string $contact = null;

    #[ORM\Column]
    private ?string $digest = null;

    #[ORM\Column]
    private ?string $token = null;

    public function rename(string $handle): void
    {
        $this->handle = $handle;
    }

    public function assignToken(?string $token): void
    {
        $this->token = $token;
    }

    public function currentToken(): ?string
    {
        return $this->token;
    }

    public function getUserIdentifier(): string
    {
        return (string) $this->handle;
    }

    public function getRoles(): array
    {
        return ['ROLE_MEMBER'];
    }

    public function getPassword(): ?string
    {
        return $this->digest;
    }

    public function eraseCredentials(): void
    {
    }
}
