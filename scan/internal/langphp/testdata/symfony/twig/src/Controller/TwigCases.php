<?php
namespace App\Controller;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
class TwigCases extends AbstractController {
    #[Route('/tw-01')]
    public function t01(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw01.html.twig', ['q' => $q]);
    }
    #[Route('/tw-02')]
    public function t02(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw02.html.twig', ['q' => $q]);
    }
    #[Route('/tw-03')]
    public function t03(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw03.html.twig', ['q' => $q]);
    }
    #[Route('/tw-04')]
    public function t04(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw04.html.twig', ['q' => $q]);
    }
    #[Route('/tw-05')]
    public function t05(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw05.html.twig', ['q' => $q]);
    }
    #[Route('/tw-06')]
    public function t06(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw06.html.twig', ['q' => $q]);
    }
    #[Route('/tw-07')]
    public function t07(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw07.html.twig', ['q' => $q]);
    }
    #[Route('/tw-08')]
    public function t08(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw08.html.twig', ['q' => $q]);
    }
    #[Route('/tw-09')]
    public function t09(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw09.html.twig', ['q' => $q]);
    }
    #[Route('/tw-10')]
    public function t10(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw10.html.twig', ['q' => $q]);
    }
    #[Route('/tw-11')]
    public function t11(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw11.html.twig', ['q' => $q]);
    }
    #[Route('/tw-12')]
    public function t12(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw12.html.twig', ['q' => $q]);
    }
    #[Route('/tw-13')]
    public function t13(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw13.html.twig', ['q' => $q]);
    }
    #[Route('/tw-14')]
    public function t14(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw14.html.twig', ['items' => [$q]]);
    }
    #[Route('/tw-15')]
    public function t15(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw15.html.twig', ['q' => $q]);
    }
    #[Route('/tw-16')]
    public function t16(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw16.html.twig', ['q' => $q]);
    }
    #[Route('/tw-17')]
    public function t17(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw17.html.twig', ['q' => $q]);
    }
    #[Route('/tw-18')]
    public function t18(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw18.html.twig', ['q' => $q]);
    }
    #[Route('/tw-19')]
    public function t19(Request $request) {
        $q = $request->query->get('q');
        return $this->render('tw19.html.twig', ['q' => $q]);
    }
    #[Route('/tw-20')]
    public function t20(Request $request) {
        $name = $request->query->get('name');
        return $this->render($name);
    }
}
