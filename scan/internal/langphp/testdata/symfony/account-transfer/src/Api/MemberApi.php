<?php
namespace App\Api;

use App\Model\Member;
use App\Store\MemberStore;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;

final class MemberApi extends AbstractController
{
    public function __construct(private MemberStore $store, private EntityManagerInterface $em)
    {
    }

    #[Route('/api/login', name: 'api_login', methods: ['POST'])]
    public function login(): JsonResponse
    {
        return new JsonResponse(['state' => 'checked']);
    }

    #[Route('/api/members', methods: ['POST'])]
    public function create(Request $request): JsonResponse
    {
        $handle = $request->request->get('handle');
        $existing = $this->store->findOneBy(['handle' => $handle]);
        if ($existing) {
            return new JsonResponse(['error' => 'handle exists'], 409);
        }
        $member = new Member();
        $member->rename($handle);
        $this->em->persist($member);
        $this->em->flush();
        return new JsonResponse(['created' => true], 201);
    }

    #[Route('/api/members/probe', methods: ['POST'])]
    public function probe(Request $request): JsonResponse
    {
        $member = $this->store->findOneBy(['handle' => $request->request->get('handle')]);
        if (null === $member) {
            return new JsonResponse(['ok' => true], 202);
        }
        return new JsonResponse(['ok' => true], 202);
    }

    #[Route('/api/members/recover', methods: ['POST'])]
    public function recover(Request $request, MailerInterface $mailer): JsonResponse
    {
        $contacts = $request->toArray()['mail'];
        $first = $this->store->findOneBy(['contact' => $contacts[0]]);
        if (null === $first) {
            return new JsonResponse(['queued' => true], 202);
        }
        $token = Uuid::v4();
        foreach ($contacts as $contact) {
            $mailer->send((new TemplatedEmail())
                ->to($contact)
                ->htmlTemplate('recover.html.twig')
                ->context(['token' => $token]));
            $this->store->findOneBy(['contact' => $contact])->assignToken($token);
        }
        $this->em->flush();
        return new JsonResponse(['queued' => true], 202);
    }

    #[Route('/api/members/confirm/{handle}/{token}', methods: ['POST'])]
    public function confirm(string $handle, string $token): JsonResponse
    {
        $member = $this->store->findOneBy(['handle' => $handle]);
        if (!$member || $member->currentToken() !== $token) {
            return new JsonResponse(['error' => 'denied'], 403);
        }
        $member->assignToken(null);
        $this->em->flush();
        return new JsonResponse(['ok' => true]);
    }
}
