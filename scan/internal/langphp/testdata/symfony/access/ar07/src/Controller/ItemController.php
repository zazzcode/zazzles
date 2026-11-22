<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class ItemController
{
    #[Route('/internal/x', name: 'item')]
    public function item(): Response
    {
        return new Response('');
    }
}
