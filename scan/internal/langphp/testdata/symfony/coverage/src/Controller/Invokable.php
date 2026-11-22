<?php
namespace App\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
#[Route('/invokable', methods: ['GET'])]
class Invokable {
    public function __invoke(Request $request): Response { return new Response($request->query->get('a')); }
}
