<?php
namespace App\Controller;

use App\Greeter;
use App\OptionalGreeting;
use ThirdParty\Unknown;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class Services
{
    #[Route('/service')]
    public function service(Request $request, Greeter $g) {
        return new Response('<p>' . $g->wrap($request->get('a')) . '</p>');
    }

    #[Route('/configuration')]
    public function configuration(Request $request, OptionalGreeting $g) {
        return $g->render($request->get('a'));
    }

    #[Route('/unknown')]
    public function unknown(Request $request, Unknown $u) {
        return new Response('<p>' . $u->run($request->get('a')) . '</p>');
    }
}
