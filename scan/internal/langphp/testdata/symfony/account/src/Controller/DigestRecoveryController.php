<?php
namespace App\Controller;

use App\Repository\Accounts;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Attribute\Route;

class DigestRecoveryController extends AbstractController
{
    #[Route('/recover/digest', methods: ['POST'])]
    public function digest(Request $request, Accounts $accounts, EntityManagerInterface $em, MailerInterface $mailer): Response
    {
        $mail = $request->get('mail');
        $account = $accounts->findOneBy(['mail' => $mail]);
        if ($account) {
            $code = md5(random_bytes(16));
            $account->setResetCode($code);
            $em->flush();
            $mailer->send((new Email())->to($mail)->text('Code: ' . $code));
        }
        return new Response('done');
    }

    #[Route('/recover/sha', methods: ['POST'])]
    public function sha(Request $request, Accounts $accounts, MailerInterface $mailer): Response
    {
        $mail = $request->get('mail');
        $account = $accounts->findOneBy(['mail' => $mail]);
        if ($account) {
            $mailer->send((new Email())->to($mail)->text('Code: ' . hash('sha256', random_bytes(32))));
        }
        return new Response('done');
    }

    #[Route('/recover/sha-weak', methods: ['POST'])]
    public function shaWeak(Request $request, MailerInterface $mailer): Response
    {
        $mailer->send((new Email())->to($request->get('mail'))->text('Code: ' . hash('sha256', uniqid())));
        return new Response('done');
    }
}
