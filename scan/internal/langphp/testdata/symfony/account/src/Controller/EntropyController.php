<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;

class EntropyController extends AbstractController
{
    #[Route('/entropy/narrow', methods: ['POST'])]
    public function narrow(Request $request, MailerInterface $mailer): Response
    {
        $code = random_int(1, 9);
        $mailer->send((new Email())->to($request->get('mail'))->text('Code: ' . $code));
        return new Response('done');
    }

    #[Route('/entropy/hex', methods: ['POST'])]
    public function hex(Request $request, MailerInterface $mailer): Response
    {
        $code = bin2hex(random_bytes(16));
        $mailer->send((new Email())->to($request->get('mail'))->text('Code: ' . $code));
        return new Response('done');
    }

    #[Route('/entropy/slice', methods: ['POST'])]
    public function slice(Request $request, MailerInterface $mailer): Response
    {
        $code = substr(bin2hex(random_bytes(16)), 0, 8);
        $mailer->send((new Email())->to($request->get('mail'))->text('Code: ' . $code));
        return new Response('done');
    }

    #[Route('/entropy/digest', methods: ['POST'])]
    public function digest(Request $request, MailerInterface $mailer): Response
    {
        $code = md5(random_bytes(32));
        $mailer->send((new Email())->to($request->get('mail'))->text('Code: ' . $code));
        return new Response('done');
    }

    #[Route('/entropy/uuid', methods: ['POST'])]
    public function uuid(Request $request, MailerInterface $mailer): Response
    {
        $code = Uuid::v4();
        $mailer->send((new Email())->to($request->get('mail'))->text('Code: ' . $code));
        return new Response('done');
    }

    #[Route('/entropy/weak', methods: ['POST'])]
    public function weak(Request $request, MailerInterface $mailer): Response
    {
        $code = uniqid();
        $mailer->send((new Email())->to($request->get('mail'))->text('Code: ' . $code));
        return new Response('done');
    }

    #[Route('/entropy/digest-slice', methods: ['POST'])]
    public function digestSlice(Request $request, MailerInterface $mailer): Response
    {
        $code = substr(sha1(random_bytes(16)), 0, 6);
        $mailer->send((new Email())->to($request->get('mail'))->text('Code: ' . $code));
        return new Response('done');
    }

    #[Route('/entropy/raw-digest-slice', methods: ['POST'])]
    public function rawDigestSlice(Request $request, MailerInterface $mailer): Response
    {
        $code = substr(md5(random_bytes(16), true), 0, 6);
        $mailer->send((new Email())->to($request->get('mail'))->text('Code: ' . $code));
        return new Response('done');
    }

    #[Route('/entropy/twice', methods: ['POST'])]
    public function twice(Request $request, MailerInterface $mailer): Response
    {
        $half = bin2hex(random_bytes(4));
        $code = $half . $half;
        $mailer->send((new Email())->to($request->get('mail'))->text('Code: ' . $code));
        return new Response('done');
    }
}
