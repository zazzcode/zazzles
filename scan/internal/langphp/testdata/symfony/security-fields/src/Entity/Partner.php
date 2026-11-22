<?php
namespace App\Entity;

use App\Service\RoleService;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
class Partner implements UserInterface
{
    #[ORM\Column]
    private string $code = '';

    private RoleService $roleService;

    public function getUserIdentifier(): string
    {
        return $this->code;
    }

    public function getRoles(): array
    {
        return $this->roleService->rolesFor($this);
    }

    public function eraseCredentials(): void
    {
    }
}
