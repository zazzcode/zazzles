<?php
namespace App\Controller;

use App\Entity\Account;
use App\Entity\Comment;
use App\Entity\Item;
use App\Entity\Post;
use App\Repository\Accounts;
use App\Repository\Items;
use App\Repository\Posts;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

class ItemController extends AbstractController
{
    #[Route('/item/{item}/gd01', methods: ['POST'])]
    public function gd01(Item $item, Request $request): Response
    {
        if ($item->getOwner() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }
        $item->setName($request->get('name'));
        return new Response('');
    }

    #[Route('/item/{item}/gd02', methods: ['POST'])]
    public function gd02(Item $item, Request $request): Response
    {
        if ($item !== $this->getUser()) {
            return new Response('');
        }
        $item->setName($request->get('name'));
        return new Response('');
    }

    #[Route('/item/{item}/gd03', methods: ['POST'])]
    public function gd03(Item $item, #[CurrentUser] Account $user, Request $request): Response
    {
        if ($item->getOwner()->getId() != $user->getId()) {
            return new Response('');
        }
        $item->setName($request->get('name'));
        return new Response('');
    }

    #[Route('/item/gd04', methods: ['POST'])]
    public function gd04(Items $repo, Request $request): Response
    {
        $item = $repo->findOneBy(['id' => $request->get('id'), 'owner' => $this->getUser()]);
        $item->setName($request->get('name'));
        return new Response('');
    }

    #[Route('/item/{item}/gd05', methods: ['POST'])]
    public function gd05(Item $item, Request $request): Response
    {
        if (!$this->isGranted('ROLE_STAFF')) {
            throw $this->createAccessDeniedException();
        }
        $item->setName($request->get('name'));
        return new Response('');
    }

    #[Route('/item/{item}/gd06', methods: ['POST'])]
    public function gd06(Item $item, Request $request): Response
    {
        if (!$this->getUser()) {
            return new Response('');
        }
        $item->setName($request->get('name'));
        return new Response('');
    }

    #[Route('/item/{account}/gd07/{code}', methods: ['POST'])]
    public function gd07(Account $account, string $code, Request $request): Response
    {
        if ($account->getResetCode() !== $code) {
            return new Response('');
        }
        $account->setGrants($request->get('grants'));
        return new Response('');
    }

    #[Route('/item/{account}/gd08', methods: ['POST'])]
    public function gd08(Request $request, Account $account): Response
    {
        if (!in_array($request->getClientIp(), ['127.0.0.1', '::1'])) {
            return new Response('', 403);
        }
        $account->setGrants($request->get('grants'));
        return new Response('');
    }

    #[Route('/item/{account}/gd09', methods: ['POST'])]
    public function gd09(Request $request, Account $account): Response
    {
        $this->allowLocal($request);
        $account->setGrants($request->get('grants'));
        return new Response('');
    }

    #[Route('/item/{account}/gd10', methods: ['POST'])]
    public function gd10(Account $account, Request $request): Response
    {
        if ($_SERVER['HTTP_X_FORWARDED_FOR'] === '10.0.0.5') {
            $account->setGrants($request->get('grants'));
        } else {
            exit;
        }
        return new Response('');
    }

    #[Route('/item/{item}/gd11', methods: ['POST'])]
    public function gd11(Item $item, Request $request): Response
    {
        if ($item->getOwner() !== $this->getUser()) {
            $this->addFlash('error', 'no');
        }
        $item->setName($request->get('name'));
        return new Response('');
    }

    #[Route('/item/{item}/gd12', methods: ['POST'])]
    public function gd12(Item $item, Request $request): Response
    {
        if (!$this->outer()) {
            return new Response('');
        }
        $item->setName($request->get('name'));
        return new Response('');
    }

    #[Route('/item/{item}/rename', methods: ['POST'])]
    public function rename(Item $item, Request $request): Response
    {
        $item->setName($request->get('name'));
        return new Response('');
    }

    #[Route('/item/self/rename', methods: ['POST'])]
    public function renameSelf(#[CurrentUser] Account $account, Request $request): Response
    {
        $account->setGrants($request->get('grants'));
        return new Response('');
    }

    #[Route('/item/{item}/remove', methods: ['POST'])]
    public function removeItem(Item $item, EntityManagerInterface $em): Response
    {
        $em->remove($item);
        return new Response('');
    }

    #[Route('/item/by-id', methods: ['POST'])]
    public function byId(Items $repo, Request $request): Response
    {
        $item = $repo->find($request->get('id'));
        $item->setName($request->get('name'));
        return new Response('');
    }

    #[Route('/item/{item}/file', methods: ['POST'])]
    public function dropFile(Item $item): Response
    {
        unlink('/tmp/' . $item->getFile());
        return new Response('');
    }

    #[Route('/portal/account/{account}/grants', methods: ['POST'])]
    public function grants(Account $account, Request $request): Response
    {
        $account->setGrants($request->get('grants'));
        return new Response('');
    }

    #[Route('/desk/account/{account}/grants', methods: ['POST'])]
    public function deskGrants(Account $account, Request $request): Response
    {
        $account->setGrants($request->get('grants'));
        return new Response('');
    }

    #[Route('/open/literal', methods: ['POST'])]
    public function literalNew(): Response
    {
        $account = new Account();
        $account->setGrants('ROLE_MEMBER');
        return new Response('');
    }

    #[Route('/open/created', methods: ['POST'])]
    public function requestNew(Request $request): Response
    {
        $account = new Account();
        $account->setGrants($request->get('grants'));
        return new Response('');
    }

    #[Route('/open/comment', methods: ['POST'])]
    public function comment(Request $request): Response
    {
        $comment = new Comment();
        $comment->setAuthor($this->getUser());
        $comment->setText($request->get('text'));
        return new Response('');
    }

    #[Route('/item/{item}/archive', methods: ['GET'])]
    public function archive(Item $item): Response
    {
        $item->setArchived(true);
        return new Response('');
    }

    #[Route('/open/mails', methods: ['GET'])]
    public function mails(Accounts $repo): Response
    {
        $account = $repo->findAll();
        return new Response($account->getMail());
    }

    #[Route('/open/titles', methods: ['GET'])]
    public function titles(Posts $repo): Response
    {
        $post = $repo->findAll();
        return new Response($post->getTitle());
    }

    #[Route('/item/{account}/mail', methods: ['GET'])]
    public function mail(Account $account): Response
    {
        return $this->render('mail.html.twig', ['account' => $account]);
    }

    #[Route('/item/{post}/title', methods: ['GET'])]
    public function title(Post $post): Response
    {
        return $this->render('title.html.twig', ['post' => $post]);
    }

    #[Route('/item/{item}/bag', methods: ['POST'])]
    public function bag(Item $item, Request $request): Response
    {
        foreach ($request->request->all() as $field => $value) {
            $item->$field = $value;
        }
        return new Response('');
    }

    #[Route('/item/{item}/peek', methods: ['GET'])]
    public function peek(Item $item): Response
    {
        $name = $item;
        return new Response('ok');
    }

    private function allowLocal(Request $request): void
    {
        if (!in_array($request->getClientIp(), ['127.0.0.1', '::1'])) {
            return new Response('', 403);
        }
    }

    private function outer(): bool
    {
        return $this->inner();
    }

    private function inner(): bool
    {
        return $this->getUser() !== null;
    }
}
