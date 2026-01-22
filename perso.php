<?php
session_start(); 
include '_conf.php';
if (isset($_POST['envoi_info'])) 
{
         
        $nom = $_POST['nom'];
        $prenom = $_POST['prenom'];
        $tel = $_POST['tel'];
        $login = $_POST['login'];
        $email = $_POST['email'];
        $id =  $_SESSION['id'];
        $connexion = mysqli_connect($serveurBDD,$userBDD,$mdpBDD,$nomBDD);
        $requete="UPDATE `utilisateur` SET 
                        `nom` = '$nom', 
                        `prenom` = '$prenom', 
                        `tel` = '$tel', 
                        `login` = '$login', 
                        `email` = '$email' 
                        WHERE `utilisateur`.`num` = $id"; 
 
        if(!mysqli_query($connexion,$requete)) 
            {
            echo "erreur";
            }
        else //si possibilit� de faire la requete :
            {
           echo "Mise � jour effectu�";
            }
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Suivi des Stages</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<?php

//*************************
//****** si il y a une valeur de session Login cela signifie que la connexion est pr�sente
//*************************
if (isset($_SESSION["login"]))
 
    {
        $id = $_SESSION["id"];
        if($_SESSION["type"]==0) //si c'est un �l�ve donc que type==0
        {
            include '_menuEleve.php';
        }
        else
        {
            include '_menuProf.php';
        }
      

        //on pr�pare la connexion avec les variables mis dans le fichier conf
        $connexion = mysqli_connect($serveurBDD,$userBDD,$mdpBDD,$nomBDD);

         //*************************
        //****** selection de tous les champs de la table UTILISATEUR en faisant une restriction sur le login 
        //*************************
        $requete="Select * from utilisateur WHERE num = '$id'"; //on initialise la requ�te
        $resultat = mysqli_query($connexion, $requete); // on ex�cute la requ�te dans la variable resultat
       
        while($donnees = mysqli_fetch_assoc($resultat)) // pour chaque ligne dans la requ�te je stock �a dans un tableau $donnees avec comme colonne le nom des champs de la requ�te SQL
         {
    
            $nom = $donnees['nom'];
          
            $prenom = $donnees['prenom'];
            $tel = $donnees['tel'];
            $login = $donnees['login'];
            $email = $donnees['email'];
         }
   
         ?>
         <!-- FORMULAIRE avec les donn�es de l'utilisateur' -->
     
         <section id="formulaire" class="form-container">
            <h2>Information Personnelle</h2>
            <form action="perso.php" method="post">
                <div class="form-group">
                    <label>Nom :</label>
                    <input type="text" name="nom" value="<?php echo $nom ?>">
                </div>
                <div class="form-group">
                    <label>Prénom :</label>
                    <input type="text" name="prenom" value="<?php echo $prenom ?>">
                </div>
                <div class="form-group">
                    <label>Tel :</label>
                    <input type="text" name="tel" value="<?php echo $tel ?>">
                </div>
                <div class="form-group">
                    <label>Login :</label>
                    <input type="text" name="login" value="<?php echo $login ?>">
                </div>
                <div class="form-group">
                    <label>Email :</label>
                    <input type="text" name="email" value="<?php echo $email ?>">
                </div>
               
                <button type="submit" class="btn-submit" name="envoi_info" value="1">Mettre à jour</button>
            </form>
        </section>


         <?php
    }


?>

</body>
</html>
