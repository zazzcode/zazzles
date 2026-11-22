<?php
namespace App\Controller;

use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class MailController extends AbstractController
{
    #[Route('/mail/one', methods: ['POST'])]
    public function one(Request $request, MailerInterface $mailer): Response
    {
        $email = (new Email())
            ->to($request->get('to'))
            ->subject('Hello')
            ->html($request->get('body'));
        $mailer->send($email);
        return new Response('sent');
    }

    #[Route('/mail/many', methods: ['POST'])]
    public function many(Request $request, MailerInterface $mailer): Response
    {
        $email = new Email();
        $email->addTo($request->get('first'));
        $email->cc($request->get('second'));
        $email->bcc($request->get('third'));
        $email->text('Plain notice');
        $mailer->send($email);
        return new Response('sent');
    }

    #[Route('/mail/templated', methods: ['POST'])]
    public function templated(Request $request, MailerInterface $mailer, UrlGeneratorInterface $router): Response
    {
        $url = $router->generate('home');
        $email = (new TemplatedEmail())
            ->to($request->get('to'))
            ->htmlTemplate('notice.html.twig')
            ->context(['link' => $url]);
        $mailer->send($email);
        return new Response('sent');
    }

    #[Route('/mail/link', methods: ['POST'])]
    public function link(Request $request, MailerInterface $mailer, UrlGeneratorInterface $router): Response
    {
        $secret = bin2hex(random_bytes(8));
        $url = $router->generate('confirm', ['code' => $secret]);
        $email = (new Email())->to($request->get('to'))->html('Open ' . $url);
        $mailer->send($email);
        return new Response('sent');
    }

    #[Route('/mail/native', methods: ['POST'])]
    public function native(Request $request): Response
    {
        $to = $request->get('to');
        $body = 'Your notice: ' . $request->get('note');
        mail($to, 'Notice', $body);
        return new Response('sent');
    }
}
