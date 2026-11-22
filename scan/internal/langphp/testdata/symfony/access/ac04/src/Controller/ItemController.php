<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class ItemController
{
    #[Route('/desk/a', name: 'a')]
    public function first(): Response
    {
        $this->denyAccessUnlessGranted('ROLE_STAFF');
        return new Response('');
    }
}
