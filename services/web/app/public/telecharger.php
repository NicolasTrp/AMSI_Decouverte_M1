<?php
// Téléchargement des factures clients.
$BASE = '/var/www/app/factures/';
$f = isset($_GET['facture']) ? $_GET['facture'] : '';

if ($f !== '') {
    // ⚠️ VULN INTENTIONNELLE (lab CTF) : le nom de fichier est concaténé tel
    // quel au chemin de base, SANS validation → PATH TRAVERSAL / lecture de
    // fichiers arbitraires (?facture=../../../../etc/passwd).
    // Bonne pratique (non appliquée exprès) : basename() + liste blanche.
    $path = $BASE . $f;
    if (is_file($path)) {
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . basename($f) . '"');
        readfile($path);
        exit;
    }
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "Facture introuvable : " . $f;
    exit;
}

// Pas de paramètre → liste des factures disponibles.
require __DIR__ . '/inc/layout.php';
lay_head('Mes factures');
?>
<section>
  <h1>Mes factures</h1>
  <p>Téléchargez vos justificatifs d'achat ShopXpress.</p>
  <ul class="files">
    <?php
    foreach (glob($BASE . '*') as $file) {
        $n = basename($file);
        echo '<li>📄 ' . htmlspecialchars($n)
           . ' — <a href="/telecharger.php?facture=' . urlencode($n) . '">télécharger</a></li>';
    }
    ?>
  </ul>
  <p class="note">Le téléchargement se fait via <code>/telecharger.php?facture=&lt;nom&gt;</code>.</p>
</section>
<?php lay_foot(); ?>
