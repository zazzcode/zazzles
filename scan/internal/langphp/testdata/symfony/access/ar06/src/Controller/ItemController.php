<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class ItemController
{
    #[Route('/api/x', name: 'get_x', methods: ['GET'])]
    public function getOne(): Response
    {
        return new Response('');
    }

    #[Route('/api/x', name: 'post_x', methods: ['POST'])]
    public function postOne(): Response
    {
        return new Response('');
    }
}
