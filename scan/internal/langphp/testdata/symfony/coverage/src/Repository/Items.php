<?php
namespace App\Repository;
use App\Entity\Item;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
class Items extends ServiceEntityRepository {
    public function search(string $q): array {
        return $this->createQueryBuilder('i')->where("i.name LIKE '%" . $q . "%'")->setMaxResults(20)->getQuery()->setFirstResult(0)->getResult();
    }
}
