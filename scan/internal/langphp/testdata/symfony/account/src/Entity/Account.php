<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
class Account implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Column]
    private ?string $mail = null;

    #[ORM\Column]
    private ?string $nick = null;

    #[ORM\Column]
    private ?string $secretHash = null;

    #[ORM\Column]
    private ?string $resetCode = null;

    public function getMail(): ?string
    {
        return $this->mail;
    }

    public function setMail(string $mail): void
    {
        $this->mail = $mail;
    }

    public function setNick(string $nick): void
    {
        $this->nick = $nick;
    }

    public function setSecretHash(string $hash): void
    {
        $this->secretHash = $hash;
    }

    public function getResetCode(): ?string
    {
        return $this->resetCode;
    }

    public function setResetCode(?string $code): void
    {
        $this->resetCode = $code;
    }

    public function getUserIdentifier(): string
    {
        return (string) $this->mail;
    }

    public function getRoles(): array
    {
        return ['ROLE_MEMBER'];
    }

    public function getPassword(): ?string
    {
        return $this->secretHash;
    }

    public function eraseCredentials(): void
    {
    }
}
