<?php
namespace App\Controller;

use App\Entity\Account;
use App\Form\AccountType;
use App\Model\Draft;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PropertyAccess\PropertyAccessorInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Serializer\SerializerInterface;

class AccountController extends AbstractController
{
    #[Route('/account/{account}/edit', methods: ['POST'])]
    public function edit(Request $request, Account $account): Response
    {
        $account->fill($request->request->all());
        return new Response('');
    }

    #[Route('/account/import', methods: ['POST'])]
    public function import(Request $request): Response
    {
        $account = new Account();
        foreach ($request->toArray() as $field => $value) {
            $account->$field = $value;
        }
        return new Response('');
    }

    #[Route('/account/{account}/setters', methods: ['POST'])]
    public function setters(Request $request, Account $account): Response
    {
        foreach ($request->request->all() as $field => $value) {
            $account->{'set' . ucfirst($field)}($value);
        }
        return new Response('');
    }

    #[Route('/account/{account}/accessor', methods: ['POST'])]
    public function accessor(Request $request, Account $account, PropertyAccessorInterface $accessor): Response
    {
        foreach ($request->query->all() as $field => $value) {
            $accessor->setValue($account, $field, $value);
        }
        return new Response('');
    }

    #[Route('/account/{account}/limited', methods: ['POST'])]
    public function limited(Request $request, Account $account): Response
    {
        $data = array_intersect_key($request->request->all(), array_flip(['name', 'bio']));
        $account->fill($data);
        return new Response('');
    }

    #[Route('/account/{account}/known', methods: ['POST'])]
    public function known(Request $request, Account $account): Response
    {
        $account->fillKnown($request->request->all());
        return new Response('');
    }

    #[Route('/account/{account}/named', methods: ['POST'])]
    public function named(Request $request, Account $account): Response
    {
        $account->setName($request->get('name'));
        $account->setBio($request->get('bio'));
        $account->setLogin($request->get('login'));
        $account->setSecret($request->get('secret'));
        $account->setGrants([$request->get('grant')]);
        return new Response('');
    }

    #[Route('/account/{account}/literal', methods: ['POST'])]
    public function literal(Request $request, Account $account): Response
    {
        $account->fill(['name' => $request->get('name')]);
        return new Response('');
    }

    #[Route('/account/{account}/defaults', methods: ['POST'])]
    public function defaults(Account $account): Response
    {
        $account->fill($this->starterValues());
        return new Response('');
    }

    #[Route('/account/{account}/form', methods: ['POST'])]
    public function form(Request $request, Account $account): Response
    {
        $form = $this->createForm(AccountType::class, $account);
        $form->handleRequest($request);
        return new Response('');
    }

    #[Route('/account/decode', methods: ['POST'])]
    public function decode(Request $request, SerializerInterface $serializer): Response
    {
        $account = $serializer->deserialize($request->getContent(), Account::class, 'json');
        return new Response('');
    }

    #[Route('/draft', methods: ['POST'])]
    public function draft(Request $request): Response
    {
        $draft = new Draft();
        foreach ($request->request->all() as $field => $value) {
            $draft->$field = $value;
        }
        return new Response('');
    }

    #[Route('/account/{account}/reflect', methods: ['POST'])]
    public function reflect(Request $request, Account $account): Response
    {
        foreach ($request->request->all() as $field => $value) {
            $idle = new \ReflectionProperty($account, $field);
            $rp = new \ReflectionProperty($account, $field);
            $rp->setValue($account, $value);
        }
        return new Response('');
    }

    #[Route('/account/{account}/inspect', methods: ['POST'])]
    public function inspect(Request $request, Account $account): Response
    {
        $rc = new \ReflectionClass($account);
        foreach ($request->request->all() as $field => $value) {
            $prop = $rc->getProperty($field);
        }
        return new Response('');
    }

    #[Route('/account/{account}/reflect-only', methods: ['POST'])]
    public function reflectOnly(Request $request, Account $account): Response
    {
        foreach ($request->request->all() as $field => $value) {
            $rp = new \ReflectionProperty($account, $field);
        }
        return new Response('');
    }

    private function starterValues(): array
    {
        return ['name' => 'guest', 'bio' => ''];
    }
}
