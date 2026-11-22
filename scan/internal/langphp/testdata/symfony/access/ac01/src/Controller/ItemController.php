<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_STAFF')]
class ItemController
{
    #[Route('/desk/a', name: 'a')]
    public function first(): Response
    {
        return new Response('');
    }

    #[Route('/desk/b', name: 'b')]
    public function second(): Response
    {
        return new Response('');
    }
}
