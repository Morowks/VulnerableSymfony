<?php

namespace App\Controller;

use App\Repository\UserRepository;
use App\Services\Mail;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class PasswordResetController extends AbstractController
{
    /**
     * FIXED: Mass assignment / account takeover — the email is now treated as a
     * single scalar value (an attacker can no longer submit an array of emails
     * to have the same reset token applied to multiple accounts). The response
     * is also constant to avoid account enumeration.
     */
    #[Route('/reset', name: 'app_reset')]
    public function index(
        Request $request,
        UserRepository $userRepository,
        EntityManagerInterface $entityManager,
        Mail $mail
    ): Response
    {

        if ($request->getMethod() === 'POST') {
            $email = $request->get('email');

            if (empty($email) || !is_string($email)) {
                $this->addFlash('error', 'A valid email is required');
                return $this->redirectToRoute('app_reset');
            }

            $user = $userRepository->findOneBy(['email' => $email]);

            // Only send a token to the matching account, and always display the
            // same message regardless of whether the account exists.
            if ($user) {
                $token = bin2hex(random_bytes(16));
                $mail->sendReset($email, $token);
            }

            $this->addFlash('success', 'If an account exists for this email, a password reset link has been sent');
        }

        return $this->render('login/reset.html.twig', [
        ]);
    }

    /**
     * Reset confirmation: the password is only changed when the token matches
     * the one stored for the account (set via the fixed /reset flow).
     */
    #[Route('/reset/{email}/{token}', name: 'app_reset_password')]
    public function resetPassword(
        Request $request,
        string $email,
        string $token,
        UserRepository $userRepository,
        EntityManagerInterface $entityManager,
    ): Response
    {

        if ($request->getMethod() === 'POST') {
            $user = $userRepository->findOneBy(['email' => $email]);
            if (!$user || $user->getReset() !== $token) {
                $this->addFlash('error', 'Invalid reset link');
                return $this->redirectToRoute('app_reset');
            }

            $password = $request->get('password');
            $confirmPassword = $request->get('confirmPassword');

            if (empty($password) || $password !== $confirmPassword) {
                $this->addFlash('error', 'Passwords do not match or are empty');
                return $this->redirectToRoute('app_reset_password', ['email' => $email, 'token' => $token]);
            }

            $user->setPassword(md5($password));
            $user->setReset(null);
            $entityManager->flush();

            $this->addFlash('success', 'Password reset successfully');
            return $this->redirectToRoute('app_login');
        }

        return $this->render('login/reset_password.html.twig', [
            'email' => $email,
            'token' => $token,
        ]);
    }
}