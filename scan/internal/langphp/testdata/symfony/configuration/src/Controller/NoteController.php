<?php
namespace App\Controller;

use App\Entity\Account;
use App\Entity\Note;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class NoteController extends AbstractController
{
    #[Route('/locked/{note}/write', methods: ['POST'])]
    public function write(Note $note, Request $request): Response
    {
        $note->setBody($request->request->get('body'));
        return new Response('');
    }

    #[Route('/locked/{note}/rename', methods: ['POST'])]
    public function rename(Note $note, Request $request): Response
    {
        $note->setBody($request->request->get('title'));
        return new Response('');
    }

    #[Route('/open/{note}/write', methods: ['POST'])]
    public function open(Note $note, Request $request): Response
    {
        $note->setBody($request->request->get('body'));
        return new Response('');
    }

    #[Route('/locked/media', methods: ['POST'])]
    public function media(Request $request): Response
    {
        $file = $request->files->get('doc');
        $file->move($this->getParameter('media_directory'), $file->getClientOriginalName());
        return new Response('');
    }

    #[Route('/locked/{account}/grants', methods: ['POST'])]
    public function grants(Request $request, Account $account): Response
    {
        if (!in_array($request->getClientIp(), ['127.0.0.1', '::1'])) {
            return new Response('', 403);
        }
        $account->setGrants($request->get('grants'));
        return new Response('');
    }
}
