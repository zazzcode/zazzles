<?php
namespace App\Controller;

use App\Repository\Accounts;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class ForgotController extends AbstractController
{
    #[Route('/forgot', methods: ['POST'])]
    public function forgot(Request $request, Accounts $accounts): Response
    {
        $account = $accounts->findOneBy(['mail' => $request->get('mail')]);
        if (!$account) {
            $this->addFlash('notice', 'No such address');
            return $this->redirectToRoute('forgot');
        }
        $this->addFlash('notice', 'Check your inbox');
        return $this->redirectToRoute('forgot');
    }

    #[Route('/forgot/quiet', methods: ['POST'])]
    public function quiet(Request $request, Accounts $accounts): Response
    {
        $account = $accounts->findOneBy(['mail' => $request->get('mail')]);
        if (empty($account)) {
            $this->addFlash('notice', 'If the address is known, a message is on its way');
            return $this->redirectToRoute('forgot');
        }
        $this->addFlash('notice', 'If the address is known, a message is on its way');
        return $this->redirectToRoute('forgot');
    }
}
