<?php
namespace App\Controller;

use App\Entity\Member;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class MemberController extends AbstractController
{
    public function held(Member $member, Request $request): Response
    {
        if ($member->getOwner()->getId() !== $this->getUser()->getId()) {
            return new Response('');
        }
        $member->setLabel($request->get('label'));
        return new Response('');
    }

    public function open(Member $member, Request $request): Response
    {
        $member->setLabel($request->get('label'));
        return new Response('');
    }

    public function portalGrants(Member $member, Request $request): Response
    {
        $member->setGrants($request->get('grants'));
        return new Response('');
    }

    public function deskGrants(Member $member, Request $request): Response
    {
        $member->setGrants($request->get('grants'));
        return new Response('');
    }
}
