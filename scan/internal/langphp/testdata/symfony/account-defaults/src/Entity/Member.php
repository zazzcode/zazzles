<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity]
class Member implements UserInterface
{
    #[ORM\Id, ORM\Column]
    private ?int $id = null;

    #[ORM\Column]
    private ?string $mail = null;
}
