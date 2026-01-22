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
include '_conf.php';
if (isset($_POST['insertion'])) //recupere données de ccr.php
{
        $date=$_POST['date'];
        $contenu= addslashes($_POST['contenu']);
        $id=$_SESSION["id"];
        $connexion = mysqli_connect($serveurBDD,$userBDD,$mdpBDD,$nomBDD);
        $requete="INSERT INTO cr (date,datetime,description,num_utilisateur) VALUES ('$date',NOW(),'$contenu','$id');"; //crée nouveau compte rendu avec infos recuperees
        echo "<br>$requete<hr>";
        if(!mysqli_query($connexion,$requete)) 
            {
            echo "erreur";
            }
        else //si possibilité de faire la requete :
            {
           echo "nouveau compte-rendu crée";
            }
}

if (isset($_POST['update'])) //recupere données de ccr.php
{
        $date=$_POST["date"];
        $description=htmlspecialchars($_POST["contenu"]);
        $idCR=$_POST["idCR"];
        $connexion = mysqli_connect($serveurBDD,$userBDD,$mdpBDD,$nomBDD);
        $requete="UPDATE `cr` SET 
                        `date` = '$date', 
                                `description` = '$description'
                                  WHERE `cr`.`num` = $idCR;"; //met à jour compte rendu avec infos recuperees

       echo "$requete";
        if(!mysqli_query($connexion,$requete)) 
            {
            echo "erreur";
            }
        else //si possibilité de faire la requete :
            {
           echo "CR modifié";
            }
}

if ($_SESSION["type"] ==1) //si connexion en prof
{
    include '_menuProf.php';
    $requete="SELECT *,DATE_FORMAT(date, '%d/%m/%Y') AS date_fr FROM cr,utilisateur WHERE utilisateur.num = cr.num_utilisateur  ORDER BY date DESC";
        if($connexion = mysqli_connect($serveurBDD,$userBDD,$mdpBDD,$nomBDD))
        {
       
            $resultat = mysqli_query($connexion, $requete);
            while($donnees = mysqli_fetch_assoc($resultat))
              {
                $num=$donnees['num'];
                $contenu=$donnees['description'];
                $prenom= $donnees['prenom'];
                $nom=$donnees['nom'];
                $date=$donnees['date_fr'];
            
                echo "<div class='table-container'><table border=2><thead> <tr> <th colspan=2> <u>n°$num ($prenom $nom) - le $date</u> </th> </tr> </thead>
                <tbody> <tr> <td>  $contenu</td> </tr>  </tbody> </table> </div>";  //affiche tous les compte rendus du plus recent au plus ancien 
              }
        }
}
else //si connexion en eleve
{ 
       include '_menuEleve.php';
        $id=$_SESSION["id"];     
        $requete="SELECT cr.*,DATE_FORMAT(date, '%d/%m/%Y') AS date_fr
            FROM cr,utilisateur WHERE utilisateur.num = cr.num_utilisateur AND utilisateur.num=$_SESSION[id] ORDER BY date DESC"; //recupere tous les comptes rendus par date decroissante
        if($connexion = mysqli_connect($serveurBDD,$userBDD,$mdpBDD,$nomBDD))
        {
       
            $resultat = mysqli_query($connexion, $requete);
            while($donnees = mysqli_fetch_assoc($resultat))
              {
                $num=$donnees['num'];
                $contenu=$donnees['description'];
                $date=$donnees['date_fr'];
            
                echo "<div class='table-container'><table border=2><thead> <tr> <th colspan=2> <u>n°$num ($date)</u> </th> </tr> </thead>
                <tbody> <tr> <td>  $contenu</td> </tr> <tr> <td> <a href='ccr.php?id=$num'>Modifier</a> </td> </tr> </tbody> </table> </div>";  //affiche tous les compte rendus du plus recent au plus ancien + lien pour modifier
              }
        }
}  

?>

</body>
</html>

