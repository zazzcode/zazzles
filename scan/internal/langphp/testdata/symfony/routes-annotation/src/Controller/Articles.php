<?php
namespace App\Controller;

use Symfony\Component\Routing\Annotation\Route;

#[Route('/blog', name: 'blog_')]
class Articles
{
    #[Route('/{slug}', methods: ['GET'])]
    public function show() {}
}
