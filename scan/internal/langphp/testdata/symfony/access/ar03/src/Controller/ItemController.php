<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class ItemController
{
    #[Route('/manage/public/info', name: 'item')]
    public function item(): Response
    {
        return new Response('');
    }
}
