<?php
namespace App\Controller;

use App\Entity\Vault;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

class VaultController
{
    #[Route('/vault', methods: ['POST'])]
    public function store(Request $request, UserPasswordHasherInterface $hasher): Response
    {
        $vault = new Vault();
        $vault->setDigest($hasher->hashPassword($vault, $request->get('phrase')));
        return new Response('');
    }
}
