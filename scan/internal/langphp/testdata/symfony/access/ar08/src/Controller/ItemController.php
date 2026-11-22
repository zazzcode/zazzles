<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class ItemController
{
    #[Route('/secret', name: 'item')]
    public function item(): Response
    {
        return new Response('');
    }
}
