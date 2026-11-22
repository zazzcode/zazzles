<?php
namespace App\Controller;

use App\Card;
use App\Settings;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

class Operations extends AbstractController {
    #[Route('/upload-client-extension')]
    public function uploadClientExtension(Request $request) {
        $file = $request->files->get('doc');
        $file->move($this->getParameter('incoming_directory'), uniqid() . '.' . $file->getClientOriginalExtension());
    }

    #[Route('/upload-list')]
    public function uploadAllowedExtension(Request $request) {
        $file = $request->files->get('doc');
        $ext = $file->guessExtension();
        if (!in_array($ext, ['png', 'jpg'], true)) {
            return;
        }
        $file->move($this->getParameter('incoming_directory'), uniqid() . '.' . $ext);
    }

    #[Route('/upload-original-name')]
    public function uploadOriginalName(Request $request) {
        $file = $request->files->get('doc');
        $directory = $this->getParameter('private_directory');
        $file->move($directory, $file->getClientOriginalName());
    }

    #[Route('/upload-temporary-name')]
    public function uploadTemporaryName(Request $request) {
        $file = $request->files->get('doc');
        $file->move($this->getParameter('incoming_directory'));
    }

    #[Route('/card', methods: ['POST'])]
    public function saveCard(Request $request, EntityManagerInterface $manager) {
        $card = new Card();
        $card->setText($request->request->get('caption'));
        $manager->persist($card);
    }

    #[Route('/card/{card}', methods: ['GET'])]
    public function showCard(Card $card) {
        return $this->render('stored.html.twig', ['card' => $card]);
    }

    #[Route('/preview')]
    public function preview(Request $request) {
        return $this->render('query.html.twig', ['caption' => $request->query->get('caption')]);
    }

    #[Route('/example')]
    public function example() {
        return $this->render('literal.html.twig');
    }

    #[Route('/settings-with-template')]
    public function renderSettings() {
        return $this->render('plain.html.twig');
    }

    #[Route('/settings-inactive')]
    public function skipSettings() {
        return $this->json('ready');
    }

    #[Route('/settings-injected')]
    public function injectSettings(Settings $settings) {
        return $this->json('ready');
    }

    #[Route('/redirect-helper')]
    public function redirectHelper(Request $request) {
        return $this->redirect($request->query->get('next'));
    }

    #[Route('/redirect-response')]
    public function redirectResponse(Request $request) {
        return new RedirectResponse($request->get('next'));
    }

    #[Route('/redirect-route')]
    public function namedRoute(Request $request) {
        return $this->redirectToRoute('home', ['m' => $request->get('m')]);
    }

    #[Route('/redirect-literal')]
    public function fixedRedirect() {
        return $this->redirect('/static');
    }

    #[Route('/evaluate-request')]
    public function evaluateRequest(Request $request) {
        return eval($request->get('code'));
    }

    #[Route('/evaluate-literal')]
    public function evaluateLiteral() {
        return eval('return 1;');
    }
}
