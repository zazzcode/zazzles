<?php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class SignInController extends AbstractController
{
    #[Route('/sign-in', name: 'sign_in', methods: ['GET', 'POST'])]
    public function signIn(): Response
    {
        return $this->render('sign_in.html.twig');
    }
}
