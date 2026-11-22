<?php
namespace App\Service;

class RoleService
{
    public function rolesFor(object $subject): array
    {
        return ['ROLE_PARTNER'];
    }
}
