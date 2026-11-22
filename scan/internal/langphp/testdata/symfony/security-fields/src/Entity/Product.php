<?php
namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Product
{
    #[ORM\Column]
    private int $price = 0;

    #[ORM\Column]
    private int $ownerId = 0;
}
