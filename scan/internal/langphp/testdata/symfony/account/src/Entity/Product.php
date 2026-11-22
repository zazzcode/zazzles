<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Product
{
    #[ORM\Column]
    private ?string $sku = null;

    public function getSku(): ?string
    {
        return $this->sku;
    }
}
