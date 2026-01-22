<?php
session_start();
include "_conf.php";

$trouve = 0;
$erreur = "";

if (isset($_POST['send_con'])) {

    $login = $_POST['login'];
    $mdp   = $_POST['mdp'];

    // Connexion à la base de données
    $bdd = mysqli_connect($serveurBDD, $userBDD, $mdpBDD, $nomBDD);

    if (!$bdd) {
        die("Erreur de connexion à la base de données : " . mysqli_connect_error());
    }

    // Requête préparée
    $requete = "SELECT * FROM utilisateur WHERE login = ?";
    $stmt = mysqli_prepare($bdd, $requete);

    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "s", $login);
        mysqli_stmt_execute($stmt);
        $resultat = mysqli_stmt_get_result($stmt);

        if ($donnees = mysqli_fetch_assoc($resultat)) {

            // Mot de passe hashé avec BCRYPT
            if (password_verify($mdp, $donnees['motdepasse'])) {
                $trouve = 1;
            }
            // Ancien mot de passe en MD5 → conversion automatique
            else if (md5($mdp) === $donnees['motdepasse']) {

                $newHash = password_hash($mdp, PASSWORD_BCRYPT);
                $update = "UPDATE utilisateur SET motdepasse=? WHERE num=?";
                $stmt2 = mysqli_prepare($bdd, $update);
                mysqli_stmt_bind_param($stmt2, "si", $newHash, $donnees['num']);
                mysqli_stmt_execute($stmt2);
                mysqli_stmt_close($stmt2);

                $trouve = 1;
            }

            // Connexion réussie
            if ($trouve === 1) {
                $_SESSION['id']    = $donnees['num'];
                $_SESSION['login'] = $donnees['login'];
                $_SESSION['type']  = $donnees['type'];
                
                // Redirection immédiate après connexion réussie
                header("Location: accueil.php");
                exit();
            }
        }

        mysqli_stmt_close($stmt);
    } else {
        $erreur = "Erreur lors de la préparation de la requête.";
    }

    if ($trouve === 0) {
        session_unset();
        session_destroy();
        $erreur = "Identifiants incorrects.";
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion - Suivi Stages</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<?php
if (isset($_SESSION['id'])) {
    if ($_SESSION['type'] == 1) {
        include '_menuProf.php';
        ?>
        <main>
            <section class="form-container">
                <h2>👨‍🏫 Bienvenue Professeur <?php echo htmlspecialchars($_SESSION['login']); ?></h2>
                <div class="welcome-message">
                    <p>Vous êtes connecté en tant que <strong>professeur</strong>.</p>
                    <div class="quick-links">
                        <button class="btn-menu" onclick="window.location.href='cr.php'">📋 Voir les comptes rendus</button>
                        <button class="btn-menu" onclick="window.location.href='perso.php'">👤 Modifier mon profil</button>
                    </div>
                </div>
            </section>
        </main>
        <?php
    } else {
        include '_menuEleve.php';
        ?>
        <main>
            <section class="form-container">
                <h2>👨‍🎓 Bienvenue Élève <?php echo htmlspecialchars($_SESSION['login']); ?></h2>
                <div class="welcome-message">
                    <p>Vous êtes connecté en tant que <strong>élève</strong>.</p>
                    <div class="quick-links">
                        <button class="btn-menu" onclick="window.location.href='cr.php'">📋 Mes comptes rendus</button>
                        <button class="btn-menu" onclick="window.location.href='ccr.php'">✏️ Nouveau compte rendu</button>
                        <button class="btn-menu" onclick="window.location.href='perso.php'">👤 Mon profil</button>
                    </div>
                </div>
            </section>
        </main>
        <?php
    }
} else {
?>
    <!-- Menu de navigation pour la page de connexion -->
    <header>
        <nav class="menu">
            <div class="logo">Suivi Stages</div>
            <div class="menu-buttons">
                <button class="btn-menu" onclick="window.location.href='index.php'">← Retour</button>
            </div>
        </nav>
    </header>

    <main>
        <section class="form-container">
            <h2>Connexion</h2>
            
            <?php if (!empty($erreur)): ?>
                <div class="error-message">
                    <h3>⚠️ Erreur de connexion</h3>
                    <p><?php echo htmlspecialchars($erreur); ?></p>
                </div>
            <?php endif; ?>
            
            <form method="post" action="">
                <div class="form-group">
                    <label>Login :</label>
                    <input type="text" name="login" placeholder="Entrez votre login" required 
                           value="<?php echo isset($_POST['login']) ? htmlspecialchars($_POST['login']) : ''; ?>">
                </div>
                <div class="form-group">
                    <label>Mot de passe :</label>
                    <input type="password" name="mdp" placeholder="Entrez votre mot de passe" required>
                </div>
                <button type="submit" class="btn-submit" name="send_con">Se connecter</button>
            </form>
            
            <div class="back-link">
                <a href="oubli.php">🔑 Mot de passe oublié ?</a><br>
                <a href="index.php">← Retour à l'accueil</a>
            </div>
        </section>
    </main>
<?php } ?>

</body>
</html>