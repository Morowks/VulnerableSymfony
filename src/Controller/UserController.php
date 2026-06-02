<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use App\Services\Avatar;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Process\Process;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

class UserController extends AbstractController
{
    #[Route('/user', name: 'app_user')]
    public function index(
        #[CurrentUser] ?User $user,
    ): Response
    {
        return $this->render('user/index.html.twig', [
            'user' => $user,
        ]);
    }

    /**
     * FIXED: Missing right control — a user may only change their own password.
     */
    #[Route('/user/password/{user}', name: 'app_user_password', methods: ['POST'])]
    public function changePassword(User $user, Request $request, UserRepository $userRepository): Response
    {
        if ($user !== $this->getUser()) {
            throw $this->createAccessDeniedException('You cannot change another user password');
        }

        $password = $request->get('newPassword');
        $confirmPassword = $request->get('confirmPassword');

        if ($password !== $confirmPassword) {
            $this->addFlash('error', 'Passwords do not match');
            return $this->redirectToRoute('app_user');
        }

        $user->setPassword(md5($password));

        $userRepository->save($user, true);

        $this->addFlash('success', 'Password changed successfully');
        return $this->redirectToRoute('app_user');
    }

    /**
     * FIXED: Missing right control / privilege escalation — a user may only
     * change their own email address.
     */
    #[Route('/user/email/{user}', name: 'app_user_email', methods: ['POST'])]
    public function changeEmail(User $user, Request $request, UserRepository $userRepository): Response
    {
        if ($user !== $this->getUser()) {
            throw $this->createAccessDeniedException('You cannot change another user email');
        }

        $email = $request->get('newEmail');

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->addFlash('error', 'Emails is not valid');
            return $this->redirectToRoute('app_user');
        }

        $user->setEmail($email);
        $userRepository->save($user, true);

        $this->addFlash('success', 'Email changed successfully');
        return $this->redirectToRoute('app_user');
    }

    /**
     * FIXED: Unrestricted file upload — the uploaded file must be a real image
     * (verified MIME type) with a whitelisted extension. The stored file name is
     * generated server-side using only that safe, whitelisted extension, so a
     * ".php" (or otherwise dangerous) file can no longer be uploaded.
     */
    #[Route('/user/avatar/{user}', name: 'app_user_avatar', methods: ['POST'])]
    public function uploadAvatar(Request $request, UserRepository $userRepository, User $user): Response
    {
        if ($user !== $this->getUser()) {
            $this->addFlash('error', 'You cannot change other users avatar');
            return $this->redirectToRoute('app_user');
        }

        $avatar = $request->files->get('avatar');

        if (empty($avatar)) {
            $this->addFlash('error', 'Avatar cannot be empty');
            return $this->redirectToRoute('app_user');
        }

        $allowed = [
            'image/png'  => 'png',
            'image/jpeg' => 'jpg',
            'image/gif'  => 'gif',
            'image/webp' => 'webp',
        ];

        $mimeType = $avatar->getMimeType();
        if (!isset($allowed[$mimeType])) {
            $this->addFlash('error', 'Only PNG, JPEG, GIF and WEBP images are allowed');
            return $this->redirectToRoute('app_user');
        }

        // If the avatar file already exists, delete it
        if (!empty($user->getAvatar()) && file_exists($this->getParameter('avatars_directory') . '/' . $user->getAvatar())) {
            unlink($this->getParameter('avatars_directory') . '/' . $user->getAvatar());
        }

        // If the avatar directory does not exist, create it
        if (!file_exists($this->getParameter('avatars_directory'))) {
            mkdir($this->getParameter('avatars_directory'));
        }

        $avatarName = md5(uniqid()) . '.' . $allowed[$mimeType];
        $avatar->move($this->getParameter('avatars_directory'), $avatarName);

        $user->setAvatar($avatarName);
        $userRepository->save($user, true);

        $this->addFlash('success', 'Avatar changed successfully');
        return $this->redirectToRoute('app_user');
    }

    /**
     * FIXED: SSRF — the URL is validated and fetched safely in
     * App\Services\Avatar (http/https only, public hosts only, no file:// etc.).
     */
    #[Route('/user/avatar/url/{user}', name: 'app_user_url_avatar', methods: ['POST'])]
    public function getAvatarFromUrl(
        Request $request,
        UserRepository $userRepository,
        User $user,
        Avatar $avatarService
    ): Response {
        if ($user !== $this->getUser()) {
            $this->addFlash('error', 'You cannot change other users avatar');
            return $this->redirectToRoute('app_user');
        }

        $url = $request->get('url');

        if (empty($url)) {
            $this->addFlash('error', 'URL cannot be empty');
            return $this->redirectToRoute('app_user');
        }
        // Get the content of the URL
        $content = $avatarService->getFromUrl($url);

        if ($content === false) {
            $this->addFlash('error', 'URL is not valid or cannot be reached');
            return $this->redirectToRoute('app_user');
        }

        // Get the file extension
        $avatarName = md5(uniqid()) . '.png';
        file_put_contents($this->getParameter('avatars_directory') . '/' . $avatarName, $content);

        $user->setAvatar($avatarName);
        $userRepository->save($user, true);

        $this->addFlash('success', 'Avatar changed successfully');
        return $this->redirectToRoute('app_user');
    }

    /**
     * FIXED: Missing right control — a user may only delete their own avatar.
     */
    #[Route('/user/avatar/delete/{user}', name: 'app_user_avatar_delete', methods: ['GET'])]
    public function deleteAvatar(User $user, UserRepository $userRepository): Response
    {
        if ($user !== $this->getUser()) {
            throw $this->createAccessDeniedException('You cannot delete another user avatar');
        }

        if (empty($user->getAvatar())) {
            $this->addFlash('error', 'No avatar to delete');
            return $this->redirectToRoute('app_user');
        }

        unlink($this->getParameter('avatars_directory') . '/' . $user->getAvatar());

        $user->setAvatar(null);
        $userRepository->save($user, true);

        $this->addFlash('success', 'Avatar deleted successfully');
        return $this->redirectToRoute('app_user');
    }

    /**
     * FIXED: Command injection — the avatar file name is no longer concatenated
     * directly into a shell string. The file name is reduced to its basename,
     * each argument is passed separately (no shell interpretation) and escaped,
     * so a crafted file name can no longer inject commands.
     */
    #[Route('/user/avatar/resize/{user}', name: 'app_user_avatar_resize', methods: ['GET'])]
    public function resizeAvatar(User $user): Response
    {
        if ($user !== $this->getUser()) {
            $this->addFlash('error', 'You cannot change other users avatar');
            return $this->redirectToRoute('app_user');
        }

        $avatar = $user->getAvatar();

        if (empty($avatar)) {
            $this->addFlash('error', 'No avatar to resize');
            return $this->redirectToRoute('app_user');
        }

        // Never trust the stored name: keep only the basename.
        $avatarFile = $this->getParameter('avatars_directory') . '/' . basename($avatar);

        if (!is_file($avatarFile)) {
            $this->addFlash('error', 'Avatar file not found');
            return $this->redirectToRoute('app_user');
        }

        // Pass arguments as an array so they are NOT interpreted by a shell.
        $process = new Process(['convert', $avatarFile, '-resize', '200x200', $avatarFile]);
        $process->run();

        $this->addFlash('success', 'Avatar resized successfully');
        return $this->redirectToRoute('app_user');
    }

    /**
     * FIXED: SSTI — the "about me" value is stored as-is but rendered escaped in
     * templates (the dangerous template_from_string() Twig function that
     * compiled user input as a template has been removed).
     */
    #[Route('/user/about/', name: 'app_user_about', methods: ['POST'])]
    public function about(
        Request $request,
        EntityManagerInterface $entityManager,
        #[CurrentUser] ?User $user
    ): Response
    {
        $about = $request->get('about');
        $user->setAboutMe($about);
        $entityManager->flush();

        $this->addFlash('success', 'About changed successfully');
        return $this->redirectToRoute('app_user');
    }

    #[Route('/user/edit/', name: 'app_user_edit_form', methods: ['GET'])]
    public function editForm(
        #[CurrentUser] ?User $user,
    ): Response
    {
        return $this->render('user/edit.html.twig', ['user' => $user]);
    }

    /**
     * FIXED: Mass assignment / privilege escalation — only an explicit whitelist
     * of safe, user-editable fields is applied. Sensitive properties such as
     * "isAdmin", "roles", "password" or "reset" can no longer be set from the
     * request body.
     */
    #[Route('/user/edit/', name: 'app_user_edit', methods: ['POST'])]
    public function edit(
        Request $request,
        EntityManagerInterface $entityManager,
        #[CurrentUser] ?User $user
    ): Response
    {
        $data = $request->request->all();

        if (isset($data['username'])) {
            $user->setUsername((string) $data['username']);
        }
        if (isset($data['firstname'])) {
            $user->setFirstname((string) $data['firstname']);
        }
        if (isset($data['lastname'])) {
            $user->setLastname((string) $data['lastname']);
        }

        $entityManager->flush();

        $this->addFlash('success', 'User changed successfully');
        return $this->redirectToRoute('app_user');
    }

}
