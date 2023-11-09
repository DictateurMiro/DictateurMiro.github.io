<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <link rel="icon" type="image/x-icon" href="images/globe.png">
  <link rel="stylesheet" href="style.css">
  <?php 
    $case_1 = htmlspecialchars($_POST['1_ip_local_v4']);
    $case_2 = htmlspecialchars($_POST['2_ip_local_v4']);
    $case_3 = htmlspecialchars($_POST['3_ip_local_v4']);
    $case_4 = htmlspecialchars($_POST['4_ip_local_v4']);
    $CIDR = htmlspecialchars($_POST['5_ip_local_v4']);
    echo "<title>IP Ciblé: ".$case_1.".".$case_2.".".$case_3.".".$case_4."/".$CIDR."</title>"; 
  ?>  
</head>
<body>

<?php

$ip_local = $case_1 . "." . $case_2 . "." . $case_3 . "." . $case_4 . "/" . $CIDR;

$ip_local_verif = $case_1 . "." . $case_2 . "." . $case_3 . "." . $case_4;

if($case_1 == ""|| $case_2 == ""|| $case_3 == ""|| $case_4 == ""|| $CIDR == ""){
  // Quand le formulaire est envoyé mais qu'il n'est pas completé
  echo "<script> location.replace('erreur/204.php'); </script>";
  exit();
}

if(!ctype_digit($case_1) || !ctype_digit($case_2) || !ctype_digit($case_3) || !ctype_digit($case_4) || !ctype_digit($CIDR)){
  // Quand il y a des lettres dans le formulaire
  echo "<script> location.replace('erreur/403.php'); </script>";
  exit();
}

if ($CIDR < 0 || $CIDR > 32) {
  // Quand le CIDR entré n'est pas compris entre 0 et 32
  echo "<script> location.replace('erreur/409.php'); </script>";
  exit();
}
if ($CIDR <= 8) {$posbarre=1;$posbarreCase = $CIDR;}
if ($CIDR > 8 && $CIDR < 16) {$posbarre = 2; $posbarreCase = $CIDR - 8; }
if ($CIDR >= 16 && $CIDR < 24) {$posbarre = 3; $posbarreCase = $CIDR - 16; }
if ($CIDR >= 24) {$posbarre = 4;$posbarreCase = $CIDR - 24; }


if(!filter_var($ip_local_verif, FILTER_VALIDATE_IP)) {
  // Quand l'adresse IP entrée n'est pas valide
  echo "<script> location.replace('erreur/203.php'); </script>";
  exit();
}

$s_case_1 = $case_1;
$s_case_2= $case_2;
$s_case_3 = $case_3;
$s_case_4 = $case_4;

$b_case_1 = $case_1;
$b_case_2= $case_2;
$b_case_3 = $case_3;
$b_case_4 = $case_4;

switch($posbarre)
  {
    //========================================================================================================
    //========================================================================================================
    case 1:
    //========================================Calcul masque================================================
    $case_1 = decbin($case_1);
    $case_1 = str_pad($case_1, 8, "0", STR_PAD_LEFT);
    $case_1 = substr($case_1, 0, $posbarreCase) . str_repeat("0", strlen($case_1) - $posbarreCase);//remplace les 1 par zéro après la barre
    $case_1 = str_repeat("1", $posbarreCase) . substr($case_1, $posbarreCase); //remplace les 0 par des 1 avant la barre
    $case_1 = bindec($case_1);
    $case_2 = 0;
    $case_3 = 0;
    $case_4 = 0;
    $masque = "{$case_1}.$case_2.$case_3.$case_4/$CIDR";

    //========================================Calcul masque iversé ================================================
    
    $case_invert_1 = 255 - $case_1;
    $case_invert_2 = 255 - $case_2;
    $case_invert_3 = 255 - $case_3;
    $case_invert_4 = 255 - $case_4;
    $masque_invert = "{$case_invert_1}.$case_invert_2.$case_invert_3.$case_invert_4/$CIDR";

    
    //========================================Calcul sous réseaux================================================
    $s_case_1 = decbin($s_case_1);
    $s_case_1 = str_pad($s_case_1, 8, "0", STR_PAD_LEFT);

    $s_case_1 = substr($s_case_1, 0, $posbarreCase) . str_repeat("0", strlen($s_case_1) - $posbarreCase);//remplace les 0 par 1 après la barre
    $s_case_1 = bindec($s_case_1);
    $s_case_2 = 0;
    $s_case_3 = 0;
    $s_case_4 = 0;
    $sous_reseau = "{$s_case_1}.$s_case_2.$s_case_3.$s_case_4";
    $s_case_1+=1;
    $first_ip = "{$s_case_1}.{$s_case_2}.{$s_case_3}.{$s_case_4}";

    //========================================Broadcast================================================
    $b_case_1 = decbin($s_case_1);
    $b_case_1 = str_pad($s_case_1, 8, "0", STR_PAD_LEFT);

    $b_case_1 = substr($s_case_1, 0, $posbarreCase) . str_repeat("1", strlen($s_case_1) - $posbarreCase); //remplace les 1 par 0 après la barre
    echo $s_case_1;
    $b_case_1 = bindec($s_case_1);
    //echo $b_case_1;
    $b_case_2 = 255;
    $b_case_3 = 255;
    $b_case_4 = 255;

    $broadcast = "{$b_case_1}.$b_case_2.$b_case_3.$b_case_4";
    $b_case_1-=1;
    $last_ip = "{$b_case_1}.{$b_case_2}.{$b_case_3}.{$b_case_4}";
    break;
    //========================================================================================================
    //========================================================================================================
    case 2:
    //========================================Calcul masque================================================

    $case_1 = 255;
    $case_2 = decbin($case_2);
    $case_2 = str_pad($case_2, 8, "0", STR_PAD_LEFT);
    $case_2 = substr($case_2, 0, $posbarreCase) . str_repeat("0", strlen($case_2) - $posbarreCase);//remplace les 1 par zéro après la barre
    $case_2 = str_repeat("1", $posbarreCase) . substr($case_2, $posbarreCase); //remplace les 0 par des 1 avant la barre
    $case_2 = bindec($case_2);
    $case_3 = 0;
    $case_4 = 0;
    $masque = "{$case_1}.$case_2.$case_3.$case_4/$CIDR";

    //========================================Calcul masque iversé ================================================

    $case_invert_1 = 255 - $case_1;
    $case_invert_2 = 255 - $case_2;
    $case_invert_3 = 255 - $case_3;
    $case_invert_4 = 255 - $case_4;
    $masque_invert = "{$case_invert_1}.$case_invert_2.$case_invert_3.$case_invert_4/$CIDR";
    
    //========================================Calcul sous réseaux================================================
    $s_case_2 = decbin($s_case_2);
    $s_case_2 = str_pad($s_case_2, 8, "0", STR_PAD_LEFT);
    $s_case_2 = substr($s_case_2, 0, $posbarreCase) . str_repeat("0", strlen($s_case_2) - $posbarreCase);//remplace les 1 par 0 après la barre
    $s_case_2 = bindec($s_case_2);
    $s_case_3 = 0;
    $s_case_4 = 0;
    $sous_reseau = "{$s_case_1}.$s_case_2.$s_case_3.$s_case_4";
    $s_case_4+=1;
    $first_ip = "{$s_case_1}.{$s_case_2}.{$s_case_3}.{$s_case_4}";

    //========================================Broadcast================================================
    $b_case_2 = decbin($b_case_2);
    $b_case_2 = str_pad($b_case_2, 8, "0", STR_PAD_LEFT);
    $b_case_2 = substr($b_case_2, 0, $posbarreCase) . str_repeat("1", strlen($b_case_2) - $posbarreCase);//remplace les 1 par 0 après la barre
    $b_case_2 = bindec($b_case_2);
    $b_case_3 = 255;
    $b_case_4 = 255;

    $broadcast = "{$b_case_1}.$b_case_2.$b_case_3.$b_case_4";
    $b_case_4-=1;
    $last_ip = "{$b_case_1}.{$b_case_2}.{$b_case_3}.{$b_case_4}";
    break;

    //========================================================================================================
    //========================================================================================================
    case 3:
    //========================================Calcul masque================================================

    $case_1 = 255;
    $case_2 = 255;
    $case_3 = decbin($case_3);
    $case_3 = str_pad($case_3, 8, "0", STR_PAD_LEFT);
    $case_3 = substr($case_3, 0, $posbarreCase) . str_repeat("0", strlen($case_3) - $posbarreCase); //remplace les 1 par zéro après la barre
    $case_3 = str_repeat("1", $posbarreCase) . substr($case_3, $posbarreCase); //remplace les 0 par des 1 avant la barre
    $case_3 = bindec($case_3);
    $case_4 = 0;
    $masque = "{$case_1}.$case_2.$case_3.$case_4/$CIDR";

    //========================================Calcul masque iversé ================================================

    $case_invert_1 = 255 - $case_1;
    $case_invert_2 = 255 - $case_2;
    $case_invert_3 = 255 - $case_3;
    $case_invert_4 = 255 - $case_4;
    $masque_invert = "{$case_invert_1}.$case_invert_2.$case_invert_3.$case_invert_4/$CIDR";
    
    //========================================Calcul sous réseaux================================================
    $s_case_3 = decbin($s_case_3);
    $s_case_3 = str_pad($s_case_3, 8, "0", STR_PAD_LEFT);

    $s_case_3 = substr($s_case_3, 0, $posbarreCase) . str_repeat("0", strlen($s_case_3) - $posbarreCase);//remplace les 0 par 1 après la barre
    $s_case_3 = bindec($s_case_3);
    $s_case_4 = 0;
    $sous_reseau = "{$s_case_1}.$s_case_2.$s_case_3.$s_case_4";
    $b_case_3+=1;
    $first_ip = "{$b_case_1}.{$b_case_2}.{$b_case_3}.{$b_case_4}";

    //========================================Broadcast================================================
    $b_case_3 = decbin($b_case_3);
    $b_case_3 = str_pad($b_case_3, 8, "0", STR_PAD_LEFT);
    $b_case_3 = substr($b_case_3, 0, $posbarreCase) . str_repeat("1", strlen($b_case_3) - $posbarreCase);//remplace les 1 par 0 après la barre
    $b_case_3 = bindec($b_case_3);
    $b_case_4 = 255;

    $broadcast = "{$b_case_1}.$b_case_2.$b_case_3.$b_case_4";
    $b_case_3-=1;
    $last_ip = "{$b_case_1}.{$b_case_2}.{$b_case_3}.{$b_case_4}";
    break;

    //========================================================================================================
    //========================================================================================================
    case 4:
    //========================================Calcul masque================================================

    $case_1 = 255;
    $case_2 = 255;
    $case_3 = 255;
    $case_4 = decbin($case_4);
    $case_4 = str_pad($case_4, 8, "0", STR_PAD_LEFT);
    $case_4 = substr($case_4, 0, $posbarreCase) . str_repeat("0", strlen($case_4) - $posbarreCase); //remplace les 1 par zéro après la barre
    $case_4 = str_repeat("1", $posbarreCase) . substr($case_4, $posbarreCase); //remplace les 0 par des 1 avant la barre
    $case_4 = bindec($case_4);
    $masque = "{$case_1}.$case_2.$case_3.$case_4/$CIDR";

    //========================================Calcul masque iversé ================================================

    $case_invert_1 = 255 - $case_1;
    $case_invert_2 = 255 - $case_2;
    $case_invert_3 = 255 - $case_3;
    $case_invert_4 = 255 - $case_4;
    $masque_invert = "{$case_invert_1}.$case_invert_2.$case_invert_3.$case_invert_4/$CIDR";
    
    //========================================Calcul sous réseaux================================================
    $s_case_4 = decbin($s_case_4);
    $s_case_4 = str_pad($s_case_4, 8, "0", STR_PAD_LEFT);

    $s_case_4 = substr($s_case_4, 0, $posbarreCase) . str_repeat("0", strlen($s_case_4) - $posbarreCase);//remplace les 0 par 1 après la barre
    $s_case_4 = bindec($s_case_4);

    $sous_reseau = "{$s_case_1}.$s_case_2.$s_case_3.$s_case_4";
    $s_case_4+=1;
    $first_ip = "{$s_case_1}.{$s_case_2}.{$s_case_3}.{$s_case_4}";
    //========================================Broadcast================================================
    $b_case_4 = decbin($b_case_4);
    $b_case_4 = str_pad($b_case_4, 8, "0", STR_PAD_LEFT);
    $b_case_4 = substr($b_case_4, 0, $posbarreCase) . str_repeat("1", strlen($b_case_4) - $posbarreCase);//remplace les 1 par 0 après la barre
    $b_case_4 = bindec($b_case_4);

    $broadcast = "{$b_case_1}.$b_case_2.$b_case_3.$b_case_4";
    $b_case_4-=1;
    $last_ip = "{$b_case_1}.{$b_case_2}.{$b_case_3}.{$b_case_4}";

    break;

  }
  
$nbhote = pow(2, (32 - $CIDR)) - 2;

echo "<div class='main'>";
echo "Adresse IP 🌐 >> $ip_local";
echo "<br><br>Le Masque du réseaux 🕶️ >> $masque";
echo "<br>Le Masque inversé 👓 >> $masque_invert";
echo "<br><br> Le Sous-réseau 💡 >> $sous_reseau";
echo "<br> L'adresse de Broadcast 📢 >> $broadcast";
echo "<br><br> La première adresse dispo : $first_ip";
echo "<br> La dernière adresse dispo : $last_ip";
echo "<br> Nombre d'hôte : $nbhote" ;
echo "<br><br><center><form action='../index.php' method='POST'><button type='submit' class='main_button'>Nouvelle IP</button></form></center></div>";
echo "<footer>Developed with the 💙 by <a href='https://github.com/DictateurMiro'>Miro</a> & <a href='https://github.com/blobs0'>Blob</a></footer>";

 /* Réponse de GPT le grand manitou :


<?php
function calculateNetworkInfo($ip, $cidr) {
    $ipLong = ip2long($ip); // Convert the IP to a long format
    $mask = -1 << (32 - $cidr); // Calculate the network mask
    $network = $ipLong & $mask; // Find the network address
    $broadcast = $network | ~$mask; // Find the broadcast address
    $numHosts = (1 << (32 - $cidr)) - 2; // Calculate number of usable hosts

    // Return an associative array with the calculated info
    return [
        'masque' => long2ip($mask),
        'sous_reseau' => long2ip($network),
        'broadcast' => long2ip($broadcast),
        'first_ip' => long2ip($network + 1),
        'last_ip' => long2ip($broadcast - 1),
        'nombre_hotes' => $numHosts
    ];
}

// Read IP address components from POST parameters
$ipComponents = array_map(function($num) { return htmlspecialchars($_POST[$num . '_ip_local_v4']); }, range(1, 4));
$cidr = htmlspecialchars($_POST['5_ip_local_v4']);
$ip = implode('.', $ipComponents); // Create the full IP string

// Validate CIDR and IP address
if ($cidr < 0 || $cidr > 32 || !filter_var($ip, FILTER_VALIDATE_IP)) {
    die("Invalid CIDR or IP address.");
}

// Calculate network information
$info = calculateNetworkInfo($ip, $cidr);

echo "Le masque 🌐 >> {$info['masque']}/$cidr<br>";
echo "Le Sous-réseau >> {$info['sous_reseau']}<br>";
echo "L'adresse de Broadcast : {$info['broadcast']}<br>";
echo "La première adresse dispo : {$info['first_ip']}<br>";
echo "La dernière adresse dispo : {$info['last_ip']}<br>";
echo "Nombre d'hôte : {$info['nombre_hotes']}";
?>



 
 */
?>

</body>
</html>
