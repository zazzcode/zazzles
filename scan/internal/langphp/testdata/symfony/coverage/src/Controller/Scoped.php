<?php
namespace App\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
#[Route('/scoped', methods: ['POST'])]
class Scoped {
    #[Route('/a')]
    public function a(Request $request): Response { return new Response($request->request->get('a')); }
}
