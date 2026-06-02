<?php

namespace App\Repository;

use App\Entity\Post;
use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<Post>
 *
 * @method Post|null find($id, $lockMode = null, $lockVersion = null)
 * @method Post|null findOneBy(array $criteria, array $orderBy = null)
 * @method Post[]    findAll()
 * @method Post[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class PostRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Post::class);
    }

    public function save(Post $entity, bool $flush = false): void
    {
        $this->getEntityManager()->persist($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function remove(Post $entity, bool $flush = false): void
    {
        $this->getEntityManager()->remove($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function total(): int
    {
        return $this->createQueryBuilder("p")
            ->select("COUNT(p.id)")
            ->getQuery()
            ->getSingleScalarResult();
    }

    public function findAllOrdered(): array
    {
        return $this->createQueryBuilder('p')
            ->orderBy('p.date', 'DESC')
            ->getQuery()
            ->getResult();
    }

    /**
     * FIXED: SQL Injection — the search term is bound as a parameter and the
     * LIKE wildcards are added to the bound value, so the input can no longer
     * break out of the string literal.
     */
    public function search(string $query): array|false
    {
        $sql = 'SELECT * FROM post WHERE content LIKE :query OR title LIKE :query ORDER BY date DESC';
        $conn = $this->getEntityManager()->getConnection();
        $stmt = $conn->prepare($sql);

        return $stmt->executeQuery([
            'query' => '%' . $query . '%',
        ])->fetchAllAssociative();
    }

    public function countByUser(User $user): int
    {
        return $this->createQueryBuilder('p')
            ->select('count(p.id)')
            ->where('p.author = :user')
            ->setParameter('user', $user)
            ->getQuery()
            ->getSingleScalarResult();
    }
}
