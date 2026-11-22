<?php
namespace App\Controller;

use Symfony\Component\Routing\Attribute\Route;

#[Route('/blog', name: 'blog_')]
class BlogController
{
    #[Route('/{slug}', methods: ['GET'])]
    public function show(string $slug) {}
}
