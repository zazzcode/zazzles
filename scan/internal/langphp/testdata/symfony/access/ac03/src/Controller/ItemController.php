<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class ItemController
{
    /**
     * @IsGranted("ROLE_STAFF")
     */
    #[Route('/desk/a', name: 'a')]
    public function first(): Response
    {
        return new Response('');
    }
}
