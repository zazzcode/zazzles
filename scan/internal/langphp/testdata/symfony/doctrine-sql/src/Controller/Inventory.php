<?php
namespace App\Controller;

use App\Repository\Stock;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

class Inventory
{
    #[Route('/sql-01')]
    public function direct(Request $r, Stock $stock) { $stock->direct($r->query->get('id')); }

    #[Route('/sql-02')]
    public function prepare(Request $r, Stock $stock) { $stock->prepare($r->query->get('id')); }

    #[Route('/sql-03')]
    public function positional(Request $r, Stock $stock) { $stock->positional($r->query->get('id')); }

    #[Route('/sql-04')]
    public function named(Request $r, Stock $stock) { $stock->named($r->query->get('id')); }

    #[Route('/sql-05')]
    public function where(Request $r, Stock $stock) { $stock->where($r->query->get('name')); }

    #[Route('/sql-06')]
    public function bound(Request $r, Stock $stock) { $stock->bound($r->query->get('name')); }

    #[Route('/sql-07')]
    public function dql(Request $r, Stock $stock) { $stock->dql($r->query->get('name')); }

    #[Route('/sql-08')]
    public function order(Request $r, Stock $stock) { $stock->order($r->query->get('sort')); }

    #[Route('/sql-09')]
    public function finder(Request $r, Stock $stock) { $stock->findOneBy(['email' => $r->query->get('email')]); }

    #[Route('/sql-10')]
    public function count(Stock $stock) { $stock->fixedCount(); }

    #[Route('/sql-11')]
    public function inherited(Request $r, Stock $stock) { $stock->inherited($r->query->get('id')); }

    #[Route('/sql-12')]
    public function unknown(Request $r, Stock $stock) { $stock->unresolved($r->query->get('id')); }
}
