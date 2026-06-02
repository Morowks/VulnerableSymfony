<?php

namespace App\Controller;

use App\Entity\Comment;
use App\Entity\Post;
use App\Repository\CommentRepository;
use App\Repository\PostRepository;
use App\Services\Analytics;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class BlogController extends AbstractController
{
    /**
     * FIXED: SSRF + RCE — Analytics::track() no longer shells out and validates
     * the referer URL (see App\Services\Analytics).
     */
    #[Route('/', name: 'app_blog')]
    public function index(PostRepository $postRepository, Analytics $analytics): Response
    {
        $analytics->track();
        return $this->render('blog/index.html.twig', [
            'posts' => $postRepository->findAllOrdered(),
        ]);
    }

    /**
     * FIXED: SSRF + RCE — Analytics::track() no longer shells out and validates
     * the referer URL (see App\Services\Analytics).
     */
    #[Route('/post/{post}', name: 'app_blog_post')]
    public function post(Post $post, CommentRepository $commentRepository, Analytics $analytics): Response
    {
        $analytics->track();
        return $this->render('blog/post.html.twig', [
            'post' => $post,
            'comments' => $commentRepository->findByPostOrdered($post->getId()),
        ]);
    }

    /**
     * FIXED: Stored XSS — the comment content is now output escaped in
     * templates/blog/post.html.twig (the "| raw" filter was removed).
     */
    #[Route('/post/{post}/comment', name: 'app_blog_post_comment', methods: ['POST'])]
    public function comment(Post $post, Request $request, CommentRepository $commentRepository): Response
    {
        // If the user is not logged in, redirect to the login page
        if (!$this->getUser()) {
            return $this->redirectToRoute('app_login');
        }

        $comment = new Comment();
        $comment->setPost($post);
        $comment->setAuthor($this->getUser());
        $comment->setContent($request->get('comment'));
        $comment->setDate(new \DateTime());
        $commentRepository->save($comment, true);

        return $this->redirectToRoute('app_blog_post', ['post' => $post->getId()]);
    }

    /**
     * FIXED: Reflected XSS — the search term is now output escaped in the
     * template (the "| raw" filter was removed).
     * FIXED: SQL Injection — PostRepository::search() now uses a parameterized
     * query.
     */
    #[Route('/search', name: 'app_blog_post_search', methods: ['GET'])]
    public function search(Request $request, PostRepository $postRepository): Response
    {
        $search = $request->get('s');
        $posts = $postRepository->search($search);

        return $this->render('blog/index.html.twig', [
            'search' => $search,
            'posts' => $posts,
        ]);
    }

    #[Route('/legal', name: 'app_legal')]
    public function legal(): Response
    {
        return $this->render('blog/legal.html.twig');
    }

    /**
     * FIXED: Local File Inclusion / path traversal — the requested file name is
     * reduced to its basename and the fully resolved path is verified to stay
     * inside the legal templates directory before anything is read.
     */
    #[Route('/legal/content', name: 'app_legal_content', methods: ['GET'])]
    public function legalContent(Request $request): Response
    {
        $baseDir = realpath(__DIR__ . '/../../templates/legal');
        $requested = (string) $request->get('p');

        // Only allow a simple file name (no directory separators / traversal).
        $fileName = basename($requested);
        if ($fileName === '' || $fileName !== $requested) {
            throw $this->createNotFoundException();
        }

        $contentPath = realpath($baseDir . DIRECTORY_SEPARATOR . $fileName);

        if (
            $contentPath === false
            || !str_starts_with($contentPath, $baseDir . DIRECTORY_SEPARATOR)
            || is_dir($contentPath)
            || !is_file($contentPath)
        ) {
            throw $this->createNotFoundException();
        }

        return new Response(file_get_contents($contentPath));
    }
}
