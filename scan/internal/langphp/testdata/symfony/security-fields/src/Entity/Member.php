<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
class Member implements UserInterface
{
    #[ORM\Column]
    private string $mail = '';

    #[ORM\Column]
    private string $tier = 'basic';

    public function getUserIdentifier(): string
    {
        return (string) $this->mail;
    }

    public function getRoles(): array
    {
        return $this->tier === 'gold' ? ['ROLE_GOLD'] : ['ROLE_BASIC'];
    }

    public function eraseCredentials(): void
    {
    }
}
