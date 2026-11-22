<?php
namespace App;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\EntityManagerInterface;
class Notes extends ServiceEntityRepository {
    public function save(Note $note, EntityManagerInterface $em) { $em->persist($note); }
}
