<?php
namespace App\Controller;

use App\Model\Draft;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class Diagnostics extends AbstractController
{
    #[Route('/diag/info', methods: ['GET'])]
    public function info(): Response
    {
        phpinfo();
        return new Response('');
    }

    #[Route('/diag/modules', methods: ['GET'])]
    public function modules(): Response
    {
        phpinfo(INFO_MODULES);
        return new Response('');
    }

    #[Route('/diag/server', methods: ['GET'])]
    public function server(): Response
    {
        var_dump($_SERVER);
        return new Response('');
    }

    #[Route('/diag/env', methods: ['GET'])]
    public function env(): Response
    {
        return new Response(print_r($_ENV, true));
    }

    #[Route('/diag/trace', methods: ['GET'])]
    public function trace(): Response
    {
        debug_print_backtrace();
        return new Response('');
    }

    #[Route('/diag/admin', methods: ['GET'])]
    public function admin(): Response
    {
        if (!$this->isGranted('ROLE_ADMIN')) {
            throw $this->createAccessDeniedException();
        }
        phpinfo();
        return new Response('');
    }

    #[Route('/diag/draft', methods: ['GET'])]
    public function draft(): Response
    {
        $draft = new Draft();
        var_dump($draft);
        return new Response('');
    }

    #[Route('/diag/text', methods: ['GET'])]
    public function text(): Response
    {
        $text = print_r($_SERVER, true);
        return new Response('ok');
    }

    #[Route('/diag/dump', methods: ['GET'])]
    public function dumpRequest(Request $request): Response
    {
        dump($request);
        return new Response('');
    }

    #[Route('/diag/uname', methods: ['GET'])]
    public function uname(): Response
    {
        return $this->render('uname.html.twig', ['u' => php_uname()]);
    }
}
