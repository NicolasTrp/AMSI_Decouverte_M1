<?php
session_start();
if (empty($_SESSION['gerant'])) { header('Location: /connexion.php'); exit; }
require __DIR__ . '/../inc/layout.php';

$msg = ''; $cls = 'ok';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['image'])) {
    // ⚠️ VULN INTENTIONNELLE (lab CTF) : AUCUN contrôle d'extension ni de type
    // MIME → on peut importer un .php qui sera EXÉCUTÉ par Apache/mod_php depuis
    // /uploads/ → RCE. Bonne pratique (non appliquée) : liste blanche d'ext.
    // image, renommage aléatoire, dossier non exécutable.
    $name = basename($_FILES['image']['name']);
    $destDir = __DIR__ . '/../uploads/';
    $dest = $destDir . $name;
    if ($_FILES['image']['error'] === UPLOAD_ERR_OK
        && move_uploaded_file($_FILES['image']['tmp_name'], $dest)) {
        $url = '/uploads/' . rawurlencode($name);
        $msg = "Fichier importé : <a href=\"" . $url . "\">" . htmlspecialchars($url) . "</a>";
    } else {
        $cls = 'err'; $msg = "Échec de l'import du fichier.";
    }
}

lay_head('Import produit');
?>
<section>
  <h1>Import d'un visuel produit</h1>
  <?php if ($msg): ?><div class="<?= $cls ?>"><?= $msg ?></div><?php endif; ?>
  <p><a href="/admin/index.php">← Retour au back-office</a></p>
</section>
<?php lay_foot(); ?>
