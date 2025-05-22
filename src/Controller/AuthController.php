<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

final class AuthController extends AbstractController
{
    #[Route('/api/register', name: 'app_register', methods: ['POST'])]
    public function register(Request $request, EntityManagerInterface $em, UserPasswordHasherInterface $passwordHasher, ValidatorInterface $validator): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        $firstName = $data['firstName'] ?? null;
        $lastName = $data['lastName'] ?? null;
        $phoneNumber = $data['phone_number'] ?? null;
        $password = $data['password'] ?? null;

        if (!$firstName || !$lastName || !$phoneNumber || !$password) {
            return new JsonResponse(['error' => 'Tous les champs sont obligatoires'], 400);
        }

        // ✅ Vérifie d'abord si le numéro est déjà utilisé
        $existingUser = $em->getRepository(User::class)->findOneBy(['phone_number' => $phoneNumber]);
        if ($existingUser) {
            return new JsonResponse(['error' => 'Ce numéro est déjà utilisé.'], 409);
        }

        // Ensuite on continue normalement
        $user = new User();
        $user->setFirstName($firstName);
        $user->setLastName($lastName);
        $user->setPhoneNumber($phoneNumber);

        $hashedPassword = $passwordHasher->hashPassword($user, $password);
        $user->setPassword($hashedPassword);

        $user->setRoles(['ROLES_USER']);
        $user->setIsVerified(false);

        $errors = $validator->validate($user);
        if ($errors->count() > 0) {
            $errorMessages = [];
            foreach ($errors as $error) {
                $errorMessages[] = $error->getMessage();
            }

            return new JsonResponse(['errors' => $errorMessages], 400);
        }

        $em->persist($user);
        $em->flush();

        return new JsonResponse(['message' => 'Utilisateur enregistré avec succès.'], 201);
    }


    #[Route('/api/login', name: 'app_login', methods: ['POST'])]
    public function login(Request $request, EntityManagerInterface $em, UserPasswordHasherInterface $passwordHasher, JWTTokenManagerInterface $jwtManager): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        $phoneNumber = $data['phone_number'] ?? null;
        $password = $data['password'] ?? null;

        if (!$phoneNumber || !$password) {
            return new JsonResponse(['error' => 'Numéro de téléphone et mot de passe requis.'], 400);
        }

        $user = $em->getRepository(User::class)->findOneBy(['phone_number' => $phoneNumber]);

        if (!$user) {
            return new JsonResponse(['error' => 'Utilisateur non trouvé.'], 404);
        }

        if (!$user->isVerified()) {
            return new JsonResponse(['error' => 'Votre compte n\'est pas encore vérifié.'], 403);
        }

        if (!$passwordHasher->isPasswordValid($user, $password)) {
            return new JsonResponse(['error' => 'Mot de passe incorrect.'], 401);
        }

        // Générer le token JWT
        $token = $jwtManager->create($user);

        return new JsonResponse([
            'token' => $token,
            'user' => [
                'id' => $user->getId(),
                'phone_number' => $user->getPhoneNumber(),
                'firstName' => $user->getFirstName(),
                'lastName' => $user->getLastName(),
            ]
        ], 200);
    }

    #[Route('/api/logout', name: 'app_logout', methods: ['POST'])]
    public function logout(): JsonResponse
    {
        return new JsonResponse(['message' => 'Déconnexion réussie.']);
    }
}
