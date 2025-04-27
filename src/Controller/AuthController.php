<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
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
}
