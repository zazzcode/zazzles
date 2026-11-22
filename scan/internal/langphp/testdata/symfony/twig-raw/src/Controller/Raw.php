<?php
namespace App\Controller;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
class Raw extends AbstractController {
    #[Route('/raw')]
    public function raw(Request $request): Response { return $this->render('raw.html.twig', ['q' => $request->query->get('q')]); }
}
