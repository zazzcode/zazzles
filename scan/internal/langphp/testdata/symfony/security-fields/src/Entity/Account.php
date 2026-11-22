<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
#[ORM\HasLifecycleCallbacks]
class Account implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column]
    private string $handle = '';

    #[ORM\Column]
    private string $secretHash = '';

    #[ORM\Column]
    private array $grants = [];

    #[ORM\Column]
    private int $staffLevel = 0;

    public function getPassword(): ?string
    {
        return $this->secretHash;
    }

    public function getUserIdentifier(): string
    {
        return $this->handle;
    }

    public function getRoles(): array
    {
        $granted = $this->grants;
        $granted[] = 'ROLE_MEMBER';
        return array_unique($granted);
    }

    #[ORM\PreUpdate]
    public function syncGrants(): void
    {
        $this->grants = $this->staffLevel > 2 ? ['ROLE_STAFF'] : [];
    }

    public function eraseCredentials(): void
    {
    }
}
