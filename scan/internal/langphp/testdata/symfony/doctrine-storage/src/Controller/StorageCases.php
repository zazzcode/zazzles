<?php
namespace App\Controller;
use App\Note;
use App\Notes;
use App\Label;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
class StorageCases extends AbstractController {
    #[Route('/note', methods: ['POST'])]
    public function add(Request $request, EntityManagerInterface $em) {
        $n = new Note();
        $n->setBody($request->get('b'));
        $em->persist($n);
    }
    #[Route('/note/save', methods: ['POST'])]
    public function save(Request $request, Notes $repo, EntityManagerInterface $em) {
        $n = new Note();
        $n->setBody($request->get('b'));
        $repo->save($n, $em);
    }
    #[Route('/note/{note}', methods: ['POST'])]
    public function replace(Request $request, Note $note, EntityManagerInterface $em) {
        $note->setBody($request->get('b'));
        $em->flush();
    }
    #[Route('/notes', methods: ['GET'])]
    public function notes(Notes $repo) {
        return $this->render('notes.html.twig', ['notes' => $repo->findAll()]);
    }
    #[Route('/note/{note}/fields', methods: ['GET'])]
    public function fields(Note $note) {
        return $this->render('fields.html.twig', ['note' => $note]);
    }
    #[Route('/note/{note}/fill', methods: ['POST'])]
    public function fill(Request $request, Note $note) {
        $note->fill($request->request->all());
    }
    #[Route('/label/{label}', methods: ['POST'])]
    public function setLabel(Label $label) {
        $label->setCaption('standard');
    }
    #[Route('/label/{label}', methods: ['GET'])]
    public function label(Label $label) {
        return $this->render('label.html.twig', ['label' => $label]);
    }
    #[Route('/flash', methods: ['POST'])]
    public function flash(Request $request) {
        $this->addFlash('notice', $request->get('m'));
        $this->addFlash('fixed', 'welcome');
    }
    #[Route('/flash', methods: ['GET'])]
    public function flashes() {
        return $this->render('flash.html.twig');
    }
}
