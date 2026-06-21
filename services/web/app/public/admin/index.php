<?php
session_start();
if (empty($_SESSION['gerant'])) { header('Location: /connexion.php'); exit; }
require __DIR__ . '/../inc/layout.php';
lay_head('Back-office');
$who = isset($_SESSION['username']) ? $_SESSION['username'] : 'gérant';
?>
<section>
  <h1>Back-office ShopXpress</h1>
  <p class="ok">Connecté en tant que <strong><?= htmlspecialchars($who) ?></strong>.
     <a href="/deconnexion.php">Se déconnecter</a></p>

  <h2>Dernières commandes</h2>
  <table class="team">
    <thead><tr><th>N°</th><th>Client</th><th>Montant</th><th>Statut</th></tr></thead>
    <tbody>
      <tr><td>2024-0142</td><td>Dupont SARL</td><td>1 249,90 €</td><td>payée</td></tr>
      <tr><td>2024-0187</td><td>Martin &amp; Fils</td><td>389,00 €</td><td>en attente</td></tr>
      <tr><td>2024-0205</td><td>Boutique Léa</td><td>74,90 €</td><td>expédiée</td></tr>
    </tbody>
  </table>

  <h2 style="margin-top:24px">Ajouter un visuel produit</h2>
  <p>Importez l'image d'un nouveau produit dans le catalogue.</p>
  <form class="box" method="post" action="/admin/upload.php" enctype="multipart/form-data">
    <label for="image">Image du produit</label>
    <input type="file" id="image" name="image">
    <button class="btn" type="submit" style="margin-top:16px">Importer</button>
  </form>
</section>
<?php lay_foot(); ?>
