<?php
namespace App\Controller;

use App\Entity\Account;
use App\Repository\Accounts;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class LookupController extends AbstractController
{
    #[Route('/sign/magic', methods: ['POST'])]
    public function magic(Request $request, Accounts $accounts): Response
    {
        $found = $accounts->findOneBySecretHash(md5($request->get('pw')));
        if (!$found) {
            $this->addFlash('error', 'Try again');
            return $this->redirectToRoute('sign_in');
        }
        return $this->redirectToRoute('home');
    }

    #[Route('/member/lookup', methods: ['POST'])]
    public function byId(Request $request, EntityManagerInterface $em): Response
    {
        $found = $em->find(Account::class, $request->get('id'));
        if (!$found) {
            $this->addFlash('error', 'No such member');
            return $this->redirectToRoute('home');
        }
        return $this->redirectToRoute('member');
    }
}
