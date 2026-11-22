<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Vault
{
    #[ORM\Column]
    private string $digest = '';

    public function setDigest(string $digest): void
    {
        $this->digest = $digest;
    }
}
