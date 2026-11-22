<?php
namespace App\Controller;

use App\Entity\Account;
use App\Repository\Accounts;
use App\Repository\Products;
use App\Service\Responder;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class JoinController extends AbstractController
{
    public function __construct(private Responder $responder)
    {
    }

    #[Route('/join', methods: ['POST'])]
    public function join(Request $request, Accounts $accounts, EntityManagerInterface $em): Response
    {
        $mail = $request->get('mail');
        $found = $accounts->findOneBy(['mail' => $mail]);
        if ($found) {
            $this->addFlash('error', 'That address is taken');
            return $this->redirectToRoute('join');
        }
        $account = new Account();
        $account->setMail($mail);
        $em->persist($account);
        $em->flush();
        return $this->redirectToRoute('home');
    }

    #[Route('/join/both', methods: ['POST'])]
    public function both(Request $request, Accounts $accounts): Response
    {
        $byMail = $accounts->findOneBy(['mail' => $request->get('mail')]);
        if ($byMail !== null) {
            $this->addFlash('error', 'Address taken');
            return $this->redirectToRoute('join');
        }
        $byNick = $accounts->findOneBy(['nick' => $request->get('nick')]);
        if (null !== $byNick) {
            $this->addFlash('error', 'Nickname taken');
            return $this->redirectToRoute('join');
        }
        return $this->redirectToRoute('home');
    }

    #[Route('/staff/join', methods: ['POST'])]
    public function staffJoin(Request $request, Accounts $accounts): Response
    {
        $found = $accounts->findOneBy(['mail' => $request->get('mail')]);
        if ($found) {
            $this->addFlash('error', 'That address is taken');
            return $this->redirectToRoute('join');
        }
        return $this->redirectToRoute('home');
    }

    #[Route('/office/join', methods: ['POST'])]
    public function officeJoin(Request $request, Accounts $accounts): Response
    {
        $found = $accounts->findOneBy(['mail' => $request->get('mail')]);
        if ($found) {
            $this->addFlash('error', 'That address is taken');
            return $this->redirectToRoute('join');
        }
        return $this->redirectToRoute('home');
    }

    #[Route('/join/linked', methods: ['POST'])]
    public function linked(Accounts $accounts): Response
    {
        $first = $accounts->find(1);
        $other = $accounts->findOneBy(['mail' => $first->getMail()]);
        if ($other) {
            $this->addFlash('error', 'Linked');
            return $this->redirectToRoute('join');
        }
        return $this->redirectToRoute('home');
    }

    #[Route('/product/check', methods: ['POST'])]
    public function product(Request $request, Products $products): Response
    {
        $item = $products->findOneBy(['sku' => $request->get('sku')]);
        if (!$item) {
            $this->addFlash('error', 'Unknown item');
            return $this->redirectToRoute('shop');
        }
        return $this->render('product.html.twig');
    }

    #[Route('/join/relay', methods: ['POST'])]
    public function relay(Request $request, Accounts $accounts): Response
    {
        $key = $request->get('key');
        $found = $accounts->findOneBy(['mail' => $request->get('mail')]);
        if ($found) {
            return $this->responder->fail($key);
        }
        return $this->redirectToRoute('home');
    }

    #[Route('/sign/check', methods: ['POST'])]
    public function check(Request $request, Accounts $accounts): Response
    {
        $found = $accounts->findOneBy(['mail' => $request->get('mail'), 'secretHash' => md5($request->get('pw'))]);
        if (!$found) {
            $this->addFlash('error', 'Try again');
            return $this->redirectToRoute('sign_in');
        }
        return $this->redirectToRoute('home');
    }
}
