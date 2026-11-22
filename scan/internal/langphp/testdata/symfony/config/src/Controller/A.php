<?php
namespace App\Controller;
use Symfony\Component\Routing\Attribute\Route;
use App\Demo;
class A
{
    #[Route('/mixed')]
    public function show(Demo $demo) {}
}
