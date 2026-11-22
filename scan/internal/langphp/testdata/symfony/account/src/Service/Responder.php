<?php
namespace App\Service;

use Symfony\Component\HttpFoundation\Response;

class Responder
{
    public function fail(string $key): Response
    {
        return new Response($key, 400);
    }
}
