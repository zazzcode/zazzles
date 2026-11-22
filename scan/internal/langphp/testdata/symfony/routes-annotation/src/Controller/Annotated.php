<?php
namespace App\Controller;

use Symfony\Component\Routing\Annotation\Route;

class Annotated
{
    /** @Route("/c", methods={"GET"}) */
    public function show() {}
}
