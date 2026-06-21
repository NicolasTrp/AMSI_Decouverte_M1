<?php
// Gabarit minimal de la boutique « ShopXpress ».
function lay_head($title) {
    $t = htmlspecialchars($title);
    echo <<<HTML
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$t — ShopXpress</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header>
  <div class="brand">🛒 ShopXpress</div>
  <nav>
    <a href="/index.php">Accueil</a>
    <a href="/produits.php">Produits</a>
    <a href="/telecharger.php">Mes factures</a>
    <a href="/apropos.php">À propos</a>
    <a href="/connexion.php">Espace gérant</a>
  </nav>
</header>
<main>
HTML;
}

function lay_foot() {
    echo <<<HTML
</main>
<footer>
  <p>ShopXpress — votre boutique high-tech en ligne. Paiement sécurisé, livraison 24h.</p>
  <!-- TODO k.dubois: retirer /telecharger.php (lecture directe de fichiers) avant la prod -->
</footer>
</body>
</html>
HTML;
}
