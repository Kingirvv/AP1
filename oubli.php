<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require __DIR__ . '/phpmailer/Exception.php';
require __DIR__ . '/phpmailer/PHPMailer.php';
require __DIR__ . '/phpmailer/SMTP.php';

include '_conf.php';

// Fonction pour générer un mot de passe aléatoire
function genererMotDePasse($longueur = 10) {
    $caracteres = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=';
    $motDePasse = '';
    for ($i = 0; $i < $longueur; $i++) {
        $motDePasse .= $caracteres[random_int(0, strlen($caracteres) - 1)];
    }
    return $motDePasse;
}

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $login = trim($_POST['login'] ?? '');

    if ($email && $login) {
        $connexion = mysqli_connect($serveurBDD, $userBDD, $mdpBDD, $nomBDD);
        if (!$connexion) {
            $message = "Erreur de connexion à la base : " . mysqli_connect_error();
        } else {
            // Requête sécurisée
            $sql = "SELECT * FROM utilisateur WHERE email = ? AND login = ?";
            if ($stmt = mysqli_prepare($connexion, $sql)) {
                mysqli_stmt_bind_param($stmt, "ss", $email, $login);
                mysqli_stmt_execute($stmt);
                $resultat = mysqli_stmt_get_result($stmt);

                if ($donnees = mysqli_fetch_assoc($resultat)) {
                    // Générer et hasher le nouveau mot de passe
                    $newmdp = genererMotDePasse();
                    $newmdphash = password_hash($newmdp, PASSWORD_BCRYPT);

                    // Mettre à jour le mot de passe
                    $sqlUpdate = "UPDATE utilisateur SET motdepasse = ? WHERE email = ? AND login = ?";
                    if ($stmtUpdate = mysqli_prepare($connexion, $sqlUpdate)) {
                        mysqli_stmt_bind_param($stmtUpdate, "sss", $newmdphash, $email, $login);
                        mysqli_stmt_execute($stmtUpdate);
                        mysqli_stmt_close($stmtUpdate);

                        // Envoi du mail
                        $mail = new PHPMailer(true);
                        try {
                            $mail->isSMTP();
                            $mail->Host = 'smtp.hostinger.com';
                            $mail->SMTPAuth = true;
                            $mail->Username = 'contact@siolapie.com';
                            $mail->Password = 'EmailL@pie25';
                            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
                            $mail->Port = 587;

                            $mail->setFrom('contact@siolapie.com', 'CONTACT SIOSLAM');
                            $mail->addAddress($email);
                            $mail->isHTML(true);
                            $mail->Subject = 'Nouveau mot de passe';
                            $mail->Body = "Voici votre nouveau mot de passe : <strong>$newmdp</strong>";

                            $mail->send();
                            $message = "✅ Un nouveau mot de passe a été envoyé à votre adresse.";
                        } catch (Exception $e) {
                            $message = "⚠️ Mot de passe mis à jour, mais erreur d'envoi de mail : " . $mail->ErrorInfo;
                        }

                    } else {
                        $message = "Erreur SQL update : " . mysqli_error($connexion);
                    }

                } else {
                    $message = "❌ Utilisateur introuvable avec cet email et login.";
                }

                mysqli_stmt_close($stmt);
            } else {
                $message = "Erreur SQL select : " . mysqli_error($connexion);
            }

            mysqli_close($connexion);
        }
    } else {
        $message = "Veuillez remplir tous les champs.";
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Mot de passe oublié</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="style.css">
</head>
<body>
<header>
    <nav class="menu">
        <div class="logo">Suivi Stages</div>
        <div class="menu-buttons">
            <button class="btn-menu" onclick="window.location.href='index.php'">Retour Index</button>
        </div>
    </nav>
</header>

<main>
    <section id="formulaire" class="form-container">
        <h2>Mot de passe oublié</h2>
        <?php if ($message): ?>
            <p><?= htmlspecialchars($message) ?></p>
        <?php endif; ?>
        <form method="post">
            <div class="form-group">
                <label>Email :</label>
                <input type="email" name="email" required>
            </div>
            <div class="form-group">
                <label>Login :</label>
                <input type="text" name="login" required>
            </div>
            <button type="submit" class="btn-submit">Recevoir un nouveau mot de passe</button>
        </form>
    </section>
</main>
</body>
</html>