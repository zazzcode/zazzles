<?php
namespace App\Controller;

use App\Repository\Accounts;
use App\Service\ResetNotifier;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class NotifyController extends AbstractController
{
    #[Route('/recover/typed', methods: ['POST'])]
    public function typed(Request $request, Accounts $accounts, ResetNotifier $notifier): Response
    {
        $addresses = $request->get('mail');
        $account = $accounts->findOneBy(['mail' => $addresses[0]]);
        if ($account) {
            $notifier->notify($addresses, bin2hex(random_bytes(16)));
        }
        return new Response('done');
    }
}
