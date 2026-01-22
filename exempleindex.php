<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Suivi des Stages</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <!-- Menu de navigation -->
    <header>
        <nav class="menu">
            <div class="logo">Suivi Stages</div>
            <ul>
                <li><a href="#accueil" class="btn">Accueil</a></li>
                <li><a href="#eleves" class="btn">Elèves</a></li>
                <li><a href="#professeurs" class="btn">Professeurs</a></li>
                <li><a href="#formulaire" class="btn">Formulaire</a></li>
            </ul>
        </nav>
    </header>

    <!-- Section principale -->
    <main>
        <section id="formulaire" class="form-container">
            <h2>Formulaire de Suivi</h2>
            <form>
                <div class="form-group">
                    <label for="nom">Nom :</label>
                    <input type="text" id="nom" name="nom" placeholder="Entrez votre nom" required>
                </div>
                <div class="form-group">
                    <label for="prenom">Pr�nom :</label>
                    <input type="text" id="prenom" name="prenom" placeholder="Entrez votre pr�nom" required>
                </div>
                <div class="form-group">
                    <label for="email">Email :</label>
                    <input type="email" id="email" name="email" placeholder="Entrez votre email" required>
                </div>
                <div class="form-group">
                    <label for="stage">Entreprise :</label>
                    <input type="text" id="stage" name="stage" placeholder="Nom de l'entreprise" required>
                </div>
                <div class="form-group">
                    <label for="date">Date de d�but :</label>
                    <input type="date" id="date" name="date" required>
                </div>
                <button type="submit" class="btn-submit">Envoyer</button>
            </form>
        </section>
    </main>
</body>
</html>
