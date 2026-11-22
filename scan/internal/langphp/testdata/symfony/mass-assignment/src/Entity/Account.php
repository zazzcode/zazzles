<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
class Account implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Column]
    private string $name = '';

    #[ORM\Column]
    private string $bio = '';

    #[ORM\Column]
    private string $login = '';

    #[ORM\Column]
    private string $secret = '';

    #[ORM\Column]
    private array $grants = [];

    public function fill(array $data): void
    {
        foreach ($data as $field => $value) {
            $this->$field = $value;
        }
    }

    public function fillKnown(array $data): void
    {
        foreach ($data as $field => $value) {
            if (property_exists($this, $field)) {
                $this->$field = $value;
            }
        }
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function setBio(string $bio): void
    {
        $this->bio = $bio;
    }

    public function setLogin(string $login): void
    {
        $this->login = $login;
    }

    public function setSecret(string $secret): void
    {
        $this->secret = $secret;
    }

    public function setGrants(array $grants): void
    {
        $this->grants = $grants;
    }

    public function getPassword(): ?string
    {
        return $this->secret;
    }

    public function getUserIdentifier(): string
    {
        return $this->login;
    }

    public function getRoles(): array
    {
        return $this->grants;
    }

    public function eraseCredentials(): void
    {
    }
}
