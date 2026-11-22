<?php
namespace App\Service;

use App\Repository\Accounts;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class ResetMailer
{
    public function __construct(
        private MailerInterface $mailer,
        private UrlGeneratorInterface $router,
        private Accounts $accounts,
        private EntityManagerInterface $em,
    ) {
    }

    public function sendAll(array $addresses, string $code): void
    {
        foreach ($addresses as $address) {
            $url = $this->router->generate('confirm', ['mail' => $address, 'code' => $code]);
            $message = (new Email())
                ->to($address)
                ->subject('Reset')
                ->html('<a href="' . $url . '">Reset</a>');
            $this->mailer->send($message);
            $account = $this->accounts->findOneBy(['mail' => $address]);
            $account->setResetCode($code);
            $this->em->flush();
        }
    }
}
