<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class ItemController
{
    #[Route('/desk/a', name: 'a')]
    #[IsGranted('EDIT', subject: 'item')]
    public function first(): Response
    {
        return new Response('');
    }
}
