<?php
namespace App\Controller;

use App\Repository\Accounts;
use App\Service\ResetMailer;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Attribute\Route;

class RecoveryController extends AbstractController
{
    #[Route('/recover/stored', methods: ['POST'])]
    public function stored(Request $request, Accounts $accounts, EntityManagerInterface $em, MailerInterface $mailer): Response
    {
        $account = $accounts->findOneBy(['mail' => $request->get('mail')]);
        if ($account) {
            $code = bin2hex(random_bytes(16));
            $account->setResetCode($code);
            $em->flush();
            $mailer->send((new Email())->to($account->getMail())->text('Code: ' . $code));
        }
        return new Response('done');
    }

    #[Route('/recover/direct', methods: ['POST'])]
    public function direct(Request $request, Accounts $accounts, EntityManagerInterface $em, MailerInterface $mailer): Response
    {
        $mail = $request->get('mail');
        $account = $accounts->findOneBy(['mail' => $mail]);
        if ($account) {
            $code = bin2hex(random_bytes(16));
            $account->setResetCode($code);
            $em->flush();
            $mailer->send((new Email())->to($mail)->text('Code: ' . $code));
        }
        return new Response('done');
    }

    #[Route('/recover/service', methods: ['POST'])]
    public function service(Request $request, Accounts $accounts, ResetMailer $resetMailer): Response
    {
        $addresses = $request->get('mail');
        $account = $accounts->findOneBy(['mail' => $addresses[0]]);
        if ($account) {
            $code = bin2hex(random_bytes(16));
            $resetMailer->sendAll($addresses, $code);
        }
        return new Response('done');
    }

    #[Route('/recover/inline', methods: ['POST'])]
    public function inline(Request $request, Accounts $accounts, EntityManagerInterface $em, MailerInterface $mailer): Response
    {
        $addresses = $request->get('mail');
        $account = $accounts->findOneBy(['mail' => $addresses[0]]);
        if ($account) {
            $code = base64_encode(random_bytes(16));
            foreach ($addresses as $address) {
                $mailer->send((new Email())->to($address)->text('Code: ' . $code));
                $accounts->findOneBy(['mail' => $address])->setResetCode($code);
            }
            $em->flush();
        }
        return new Response('done');
    }

    #[Route('/recover/blind', methods: ['POST'])]
    public function blind(Request $request, MailerInterface $mailer): Response
    {
        $code = bin2hex(random_bytes(16));
        $mailer->send((new Email())->to($request->get('mail'))->text('Code: ' . $code));
        return new Response('done');
    }

    #[Route('/recover/weak', methods: ['POST'])]
    public function weak(Request $request, Accounts $accounts, EntityManagerInterface $em, MailerInterface $mailer): Response
    {
        $account = $accounts->findOneBy(['mail' => $request->get('mail')]);
        if ($account) {
            $code = uniqid();
            $account->setResetCode($code);
            $em->flush();
            $mailer->send((new Email())->to($account->getMail())->text('Code: ' . $code));
        }
        return new Response('done');
    }

    #[Route('/recover/echo', methods: ['POST'])]
    public function echoNote(Request $request, MailerInterface $mailer): Response
    {
        $mailer->send((new Email())->to($request->get('mail'))->text('Note: ' . $request->get('note')));
        return new Response('done');
    }

    #[Route('/recover/confirm/{mail}/{code}', methods: ['POST'])]
    public function confirm(Request $request, string $mail, string $code, Accounts $accounts, EntityManagerInterface $em): Response
    {
        $account = $accounts->findOneBy(['mail' => $mail]);
        if (!$account || $account->getResetCode() !== $code) {
            return new Response('invalid', 403);
        }
        $account->setSecretHash(password_hash($request->get('pw'), PASSWORD_DEFAULT));
        $account->setResetCode(null);
        $em->flush();
        return new Response('changed');
    }
}
