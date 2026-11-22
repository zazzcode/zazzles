<?php
namespace App\Repository;

use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\EntityManagerInterface;

class Stock extends ServiceEntityRepository
{
    public function __construct(private Connection $conn, private EntityManagerInterface $em) {}

    public function direct($id)
    {
        return $this->conn->executeQuery('SELECT * FROM stock WHERE id = ' . $id);
    }

    public function prepare($id)
    {
        $sql = 'SELECT * FROM stock WHERE id = ' . $id;
        $statement = $this->conn->prepare($sql);
        return $statement->executeQuery([]);
    }

    public function positional($id)
    {
        return $this->conn->executeQuery('SELECT * FROM stock WHERE id = ?', [$id]);
    }

    public function named($id)
    {
        $statement = $this->conn->prepare('SELECT * FROM stock WHERE id = :id');
        $statement->bindValue('id', $id);
        return $statement->executeQuery();
    }

    public function where($name)
    {
        return $this->createQueryBuilder('s')->where("s.name = '" . $name . "'")->getQuery()->getResult();
    }

    public function bound($name)
    {
        return $this->createQueryBuilder('s')->where('s.name = :n')->setParameter('n', $name)->getQuery()->getResult();
    }

    public function dql($name)
    {
        return $this->em->createQuery("SELECT s FROM App\\Entity\\Item s WHERE s.name = '" . $name . "'")->getResult();
    }

    public function order($sort)
    {
        $builder = $this->createQueryBuilder('s');
        $builder->orderBy('s.' . $sort, 'ASC');
        return $builder->getQuery()->getResult();
    }

    public function fixedCount()
    {
        return $this->createQueryBuilder('s')->select('count(s.id)')->getQuery()->getSingleScalarResult();
    }

    public function inherited($id)
    {
        $sql = 'SELECT * FROM stock WHERE id = ' . $id;
        $statement = $this->getEntityManager()->getConnection()->prepare($sql);
        return $statement->executeQuery([]);
    }

    public function unresolved($id, $connection = null)
    {
        $sql = 'SELECT * FROM stock WHERE id = ' . $id;
        return $connection->executeQuery($sql);
    }
}
