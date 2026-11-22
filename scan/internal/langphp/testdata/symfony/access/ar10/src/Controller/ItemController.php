<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class ItemController
{
    #[Route('/item/{id}/edit', name: 'item')]
    public function item(): Response
    {
        return new Response('');
    }
}
