<?php
namespace App\Controller;
use App\Entity\Item;
use App\Repository\Items;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
class Cases extends AbstractController {
    #[Route('/in/digits/{id<\d+>}')]
    public function digits(string $id): Response { return new Response($id); }
    #[Route('/in/word/{slug<[a-z-]+>}')]
    public function word(string $slug): Response { return new Response($slug); }
    #[Route('/in/optional/{page?1}')]
    public function optional(string $page): Response { return new Response($page); }
    #[Route('/in/suffix/{slug}.html')]
    public function suffix(string $slug): Response { return new Response($slug); }
    #[Route('/in/typed/{id}')]
    public function typed(int $id): Response { return new Response('n' . $id); }
    #[Route('/in/string')]
    public function getString(Request $request): Response { return new Response($request->query->getString('a')); }
    #[Route('/in/json', methods: ['POST'])]
    public function json(Request $request): Response { $data = json_decode($request->getContent(), true); return new Response($data['a']); }
    #[Route('/in/cast')]
    public function cast(Request $request): Response { return new Response('n' . (int) $request->query->get('a')); }
    #[Route('/in/sprintf')]
    public function sprintfText(Request $request): Response { return new Response(sprintf('<b>%s</b>', $request->query->get('a'))); }
    #[Route('/in/sprintf-number')]
    public function sprintfNumber(Request $request): Response { return new Response(sprintf('<b>%d</b>', $request->query->get('a'))); }
    #[Route('/in/implode')]
    public function implode(Request $request): Response { return new Response(implode(',', $request->query->all('ids'))); }
    #[Route('/out/content')]
    public function content(Request $request): Response { $r = new Response(); $r->setContent($request->query->get('a')); return $r; }
    #[Route('/out/plain')]
    public function plain(Request $request): Response { $r = new Response(); $r->headers->set('Content-Type', 'text/plain'); $r->setContent($request->query->get('a')); return $r; }
    #[Route('/cmd/backtick')]
    public function backtick(Request $request): Response { $h = $request->query->get('h'); $o = `ping $h`; return new Response('ok'); }
    #[Route('/sql/builder')]
    public function builder(Request $request, EntityManagerInterface $em): Response { $em->createQueryBuilder()->select('i')->from(Item::class, 'i')->where("i.name = '" . $request->query->get('n') . "'")->getQuery()->getResult(); return new Response('ok'); }
    #[Route('/sql/bound')]
    public function bound(Request $request, EntityManagerInterface $em): Response { $em->createQueryBuilder()->select('i')->from(Item::class, 'i')->where('i.name = :n')->setParameter('n', $request->query->get('n'))->setMaxResults(3)->getQuery()->getResult(); return new Response('ok'); }
    #[Route('/sql/paged')]
    public function paged(Request $request, EntityManagerInterface $em): Response { $em->createQuery("SELECT i FROM App\Entity\Item i WHERE i.name = '" . $request->query->get('n') . "'")->setMaxResults(10)->getResult(); return new Response('ok'); }
    #[Route('/sql/repository')]
    public function repository(Request $request, Items $items): Response { $items->search($request->query->get('q')); return new Response('ok'); }
    #[Route('/store/write', methods: ['POST'])]
    public function write(Request $request, EntityManagerInterface $em): Response { $i = new Item(); $i->setName($request->request->get('name')); $em->persist($i); $em->flush(); return new Response('ok'); }
    #[Route('/store/read/{id}')]
    public function read(Item $item): Response { return new Response('<h1>' . $item->getId() . ' ' . $item->getName() . '</h1>'); }
    #[Route('/store/id/{id}')]
    public function identifier(Item $item): Response { return new Response('<h1>' . $item->getId() . '</h1>'); }
    #[Route('/flash')]
    public function flash(): Response { return $this->render('flash.html.twig'); }
    #[Route('/tw/{name}')]
    public function twig(Request $request, string $name): Response { return $this->render('tw.html.twig', ['q' => $request->query->get('q')]); }
}
