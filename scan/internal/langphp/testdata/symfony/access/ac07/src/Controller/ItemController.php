<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class ItemController
{
    /**
     * @Security("is_granted('ROLE_X') and is_granted('ROLE_Y')")
     */
    #[Route('/desk/a', name: 'a')]
    public function first(): Response
    {
        return new Response('');
    }
}
