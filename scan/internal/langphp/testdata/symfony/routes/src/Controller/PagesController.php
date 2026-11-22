<?php
namespace App\Controller;

use Symfony\Component\Routing\Attribute\Route;

class PagesController
{
    #[Route('/a', methods: ['GET', 'POST'])]
    public function submit() {}

    #[Route('/b')]
    public function browse() {}

    #[Route('/first')]
    #[Route('/second')]
    public function aliases() {}

    #[Route($path)]
    public function dynamic() {}
}
