<?php

namespace App\Services;

use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class Mail
{
    public function __construct(
        private string $sender,
        private MailerInterface $mailer,
        private UrlGeneratorInterface $router,
        private UserRepository $userRepository,
        private EntityManagerInterface $entityManager,
    ) {}

    /**
     * FIXED: account takeover — the reset token is only ever generated and
     * stored for the single, verified email address (no array of recipients).
     */
    public function sendReset(string $emailAddress, string $token): void
    {
        $user = $this->userRepository->findOneBy(['email' => $emailAddress]);
        if (!$user) {
            return;
        }

        $url = $this->router->generate('app_reset_password', [
            'email' => $emailAddress,
            'token' => $token
        ], UrlGeneratorInterface::ABSOLUTE_URL);

        $email = (new Email())
            ->from($this->sender)
            ->to($emailAddress)
            ->subject('Reset your password')
            ->html('<p>Click <a href="'.$url.'">here</a> to reset your password</p>');

        $this->mailer->send($email);

        $user->setReset($token);
        $this->entityManager->flush();
    }
}