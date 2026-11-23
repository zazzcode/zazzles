<?php
namespace App\Controller;

use App\Service\Pinger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Process\Process;
use Symfony\Component\Routing\Attribute\Route;

class FetchController
{
    #[Route('/su10')]
    public function su10(Request $request): Response
    {
        $url = $request->query->get('u');
        $process = new Process(['curl', '-s', $url]);
        return new Response('');
    }

    #[Route('/su11')]
    public function su11(Request $request): Response
    {
        $name = $request->query->get('n');
        $process = new Process(['curl', '-o', $name, 'https://example.org/a']);
        return new Response('');
    }

    #[Route('/su14')]
    public function su14(Request $request, Pinger $pinger): Response
    {
        $pinger->ping($request->headers->get('referer'));
        return new Response('');
    }

    #[Route('/argv-proxy')]
    public function argvProxy(Request $request): Response
    {
        $process = new Process(['curl', '--proxy=' . $request->query->get('p'), 'https://example.org/a']);
        return new Response('');
    }

    #[Route('/su12')]
    public function su12(Request $request, Pinger $pinger): Response
    {
        $pinger->checked($request->headers->get('referer'));
        return new Response('');
    }
}
