<?php
namespace App\Controller;

use App\Entity\Member;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class ProfileController
{
    /**
     * @Route("/profile/{member}/apply", methods={"PUT"})
     */
    public function apply(Request $request, Member $member): Response
    {
        foreach ($request->getPayload()->all() as $attribute => $content) {
            $setter = 'set' . ucfirst($attribute);
            $member->$setter($content);
        }
        return new Response('');
    }

    /**
     * @Route("/profile/{member}/motto", methods={"PUT"})
     */
    public function motto(Request $request, Member $member): Response
    {
        $member->setNickname($request->getPayload()->get('nickname'));
        $member->setMotto($request->getPayload()->get('motto'));
        return new Response('');
    }
}
