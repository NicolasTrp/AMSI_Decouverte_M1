<?php
// Gabarit minimal du site « Licornia Parc ».
function lay_head($title) {
    $t = htmlspecialchars($title);
    echo <<<HTML
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$t — Licornia Parc</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header>
  <div class="brand">🦄 Licornia&nbsp;Parc</div>
  <nav>
    <a href="/index.php">Accueil</a>
    <a href="/equipe.php">Notre équipe</a>
    <a href="/outils.php">Diagnostic réseau</a>
    <a href="/brochure-licornia.jpg">Brochure</a>
  </nav>
</header>
<main>
HTML;
}

function lay_foot() {
    echo <<<HTML
</main>
<footer>
  <p>Licornia Parc — le parc à licornes de la région. Site interne, usage réservé au personnel.</p>
  <!-- TODO theo: penser à retirer la page /outils.php de la prod (debug réseau) -->
</footer>
</body>
</html>
HTML;
}
