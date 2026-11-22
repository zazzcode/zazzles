<?php
namespace App\Controller;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
class ResponseCases extends AbstractController {
    #[Route('/rs-01')]
    public function html(Request $r) {
        $q = $r->query->get('q');
        return new Response('<p>' . $q . '</p>');
    }
    #[Route('/rs-02')]
    public function jsonResponses(Request $r) {
        $q = $r->query->get('q');
        $response = new JsonResponse(['q' => $q]);
        return $this->json($q);
    }
    #[Route('/rs-03')]
    public function plain(Request $r) {
        $q = $r->query->get('q');
        return new Response($q, 200, ['Content-Type' => 'text/plain']);
    }
    #[Route('/rs-04')]
    public function dynamic(Request $r) {
        $q = $r->query->get('q');
        $type = $r->query->get('type');
        return new Response($q, 200, ['Content-Type' => $type]);
    }
    #[Route('/headers/plain')]
    public function headerPlain(Request $r) {
        $response = new Response($r->query->get('q'));
        $response->headers->set('Content-Type', 'text/plain');
        return $response;
    }
    #[Route('/headers/html')]
    public function headerHtml(Request $r) {
        $response = new Response($r->query->get('q'), 200, ['Content-Type' => 'text/plain']);
        $response->headers->set('Content-Type', 'text/html');
        return $response;
    }
    #[Route('/headers/dynamic')]
    public function headerDynamic(Request $r) {
        $response = new Response($r->query->get('q'));
        $response->headers->set('Content-Type', $r->query->get('type'));
        return $response;
    }
}
