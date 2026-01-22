<?php
session_start(); 
include '_conf.php';
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Suivi des Stages</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<?php

//*************************
//****** si il y a une valeur de session Login cela signifie que la connexion est présente
//*************************
if (isset($_SESSION["login"]))
 
    {
        if($_SESSION["type"]==0) //si c'est un élève donc que type==0
        {
            include '_menuEleve.php';
            if(isset($_GET["id"]))
            {
                $idCR=$_GET["id"];
                $iduser=$_SESSION["id"];
                 //on prépare la connexion avec les variables mis dans le fichier conf
                    $connexion = mysqli_connect($serveurBDD,$userBDD,$mdpBDD,$nomBDD);

                     //*************************
                    //****** selection de tous les champs de la table UTILISATEUR en faisant une restriction sur le login 
                    //*************************
                    $requete="Select * from cr WHERE num = '$idCR' and num_utilisateur= $iduser"; //on initialise la requête
                    $resultat = mysqli_query($connexion, $requete); // on exécute la requête dans la variable resultat
                    $trouve=0;
                    while($donnees = mysqli_fetch_assoc($resultat)) // pour chaque ligne dans la requête je stock ça dans un tableau $donnees avec comme colonne le nom des champs de la requête SQL
                     {
                        $trouve=1;
                        $date = $donnees['date'];
                        $description=  $donnees['description'];                 
                     }    
            
                    if ($trouve==1) {?>
                         <section id="formulaire" class="form-container">
                        <h2>Modifier un CR</h2>
                        <form action="cr.php" method="post">

                          <div class="form-group">
                                <label>Date du CR :</label>
                                <input type="date" name="date" value="<?php echo $date ?>"> 
                          </div>
                          <div class="form-group">
                                <label>Contenu :</label>
                                <textarea name="contenu" rows=10 required ><?php echo $description ?></textarea>
                          </div>
                          <input type="hidden" name="idCR" value="<?php echo $idCR ?>"> 
                           <button type="submit" class="btn-submit" name="update"> Modifier </button>
                        </form>
                         </section>

            <?php
                    }
                    else
                    {
                        echo "erreur";
                    }
            }
            else {


            ?>
            
            <section id="formulaire" class="form-container">
            <h2>Créer un CR</h2>
            <form action="cr.php" method="post">

              <div class="form-group">
                    <label>Date du CR :</label>
                    <input type="date" name="date" required> 
              </div>
              <div class="form-group">
                    <label>Contenu :</label>
                    <textarea name="contenu" rows=10 required placeholder="Entrez votre CR ici"></textarea>
              </div>
               <button type="submit" class="btn-submit" name="insertion" > Confirmer </button>
            </form>
             </section>
        <?php
            }
        }
        else
        {
            include '_menuProf.php';
        }

    }


?>
</body>
</html>




