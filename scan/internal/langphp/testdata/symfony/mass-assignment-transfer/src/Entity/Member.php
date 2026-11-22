<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
class Member implements UserInterface
{
    #[ORM\Column]
    private string $nickname = '';

    #[ORM\Column]
    private string $motto = '';

    #[ORM\Column]
    private int $staffLevel = 0;

    public function setNickname(string $nickname): void
    {
        $this->nickname = $nickname;
    }

    public function setMotto(string $motto): void
    {
        $this->motto = $motto;
    }

    public function setStaffLevel(int $staffLevel): void
    {
        $this->staffLevel = $staffLevel;
    }

    public function getUserIdentifier(): string
    {
        return $this->nickname;
    }

    public function getRoles(): array
    {
        return $this->staffLevel > 1 ? ['ROLE_STAFF'] : ['ROLE_GUEST'];
    }

    public function eraseCredentials(): void
    {
    }
}
