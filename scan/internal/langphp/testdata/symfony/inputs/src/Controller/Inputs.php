<?php
namespace App\Controller;

use App\Post;
use App\User;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\MapQueryParameter;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

class Inputs
{
    #[Route('/query')]
    public function query(Request $request) {
        return new Response('<p>' . $request->query->get('q') . '</p>');
    }

    #[Route('/form')]
    public function form(Request $request) {
        return new Response('<p>' . $request->request->get('b') . '</p>');
    }

    #[Route('/any')]
    public function any(Request $request) {
        return new Response('<p>' . $request->get('a') . '</p>');
    }

    #[Route('/headers')]
    public function headers(Request $request) {
        return new Response('<p>' . $request->headers->get('X-Tag') . $request->cookies->get('c') . '</p>');
    }

    #[Route('/item/{id}')]
    public function item(string $id) {
        return new Response('<p>' . $id . '</p>');
    }

    #[Route('/mapped')]
    public function mapped(#[MapQueryParameter] string $q) {
        return new Response('<p>' . $q . '</p>');
    }

    #[Route('/number')]
    public function number(Request $request) {
        return new Response('<p>' . $request->query->getInt('n') . '</p>');
    }

    #[Route('/body')]
    public function body(Request $request) {
        return new Response('<p>' . $request->getContent() . '</p>');
    }

    #[Route('/post/{post}')]
    public function post(Post $post) {
        return new Response('<p>' . $post->getTitle() . '</p>');
    }

    #[Route('/me')]
    public function me(#[CurrentUser] User $user) {
        return new Response('<p>' . $user->getName() . '</p>');
    }

    #[Route('/method', methods: ['GET', 'POST'])]
    public function method(Request $request) {
        if ($request->isMethod('POST')) {
            return new Response('<p>' . $request->get('a') . '</p>');
        }
    }
}
