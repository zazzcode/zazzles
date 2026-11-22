<?php
namespace App\Controller;

use App\Entity\Account;
use App\Entity\Operator;
use App\Repository\Accounts;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

class ProfileController extends AbstractController
{
    #[Route('/profile/plain', methods: ['POST'])]
    public function plain(Request $request, EntityManagerInterface $em): Response
    {
        $account = new Account();
        $account->setSecretHash(md5($request->get('pw')));
        $em->persist($account);
        $em->flush();
        return new Response('saved');
    }

    #[Route('/profile/salted', methods: ['POST'])]
    public function salted(Request $request, Accounts $accounts, EntityManagerInterface $em): Response
    {
        $account = $accounts->find(1);
        $salt = $account->getMail();
        $account->setSecretHash(sha1($salt . $request->get('pw')));
        $em->flush();
        return new Response('saved');
    }

    #[Route('/profile/sha256', methods: ['POST'])]
    public function sha256(Request $request, EntityManagerInterface $em): Response
    {
        $account = new Account();
        $account->setSecretHash(hash('sha256', $request->get('pw')));
        $em->persist($account);
        $em->flush();
        return new Response('saved');
    }

    #[Route('/profile/adaptive', methods: ['POST'])]
    public function adaptive(Request $request, EntityManagerInterface $em): Response
    {
        $account = new Account();
        $account->setSecretHash(password_hash($request->get('pw'), PASSWORD_DEFAULT));
        $em->persist($account);
        $em->flush();
        return new Response('saved');
    }

    #[Route('/profile/operator', methods: ['POST'])]
    public function operator(Request $request, UserPasswordHasherInterface $hasher, EntityManagerInterface $em): Response
    {
        $operator = new Operator();
        $operator->setPasswordDigest($hasher->hashPassword($operator, $request->get('pw')));
        $em->persist($operator);
        $em->flush();
        return new Response('saved');
    }

    #[Route('/profile/names', methods: ['POST'])]
    public function names(Request $request, Accounts $accounts, EntityManagerInterface $em): Response
    {
        $account = $accounts->find(1);
        $account->setNick(md5(uniqid()));
        $cacheKey = md5($request->get('sku'));
        $em->flush();
        return new Response($cacheKey === '' ? 'none' : 'ok');
    }

    #[Route('/profile/crypt', methods: ['POST'])]
    public function cryptPw(Request $request, EntityManagerInterface $em): Response
    {
        $account = new Account();
        $account->setSecretHash(crypt($request->get('pw'), '$2y$10$fixedsaltfixedsalt'));
        $em->persist($account);
        $em->flush();
        return new Response('saved');
    }
}
