<?php
session_start();
// Base du back-office (chemin issu de la conf laissée par le dev).
$DB_PATH = '/var/www/app/data/shop.db';
@include __DIR__ . '/../config/config.php';   // peut redéfinir $DB_PATH

$err = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = isset($_POST['user']) ? $_POST['user'] : '';
    $pass = isset($_POST['pass']) ? $_POST['pass'] : '';

    // ⚠️ VULN INTENTIONNELLE (lab CTF) : la saisie est concaténée directement
    // dans la requête SQL → INJECTION SQL / contournement d'authentification.
    // Bonne pratique (non appliquée exprès) : requête préparée + bindValue().
    $q = "SELECT * FROM users WHERE username='" . $user . "' AND password='" . $pass . "'";

    try {
        $db = new SQLite3($DB_PATH, SQLITE3_OPEN_READONLY);
        $res = @$db->query($q);
        $row = $res ? $res->fetchArray(SQLITE3_ASSOC) : false;
        if ($row) {
            $_SESSION['gerant'] = 1;
            $_SESSION['username'] = $row['username'];
            header('Location: /admin/index.php');
            exit;
        }
        $err = "Identifiants invalides.";
    } catch (Exception $e) {
        $err = "Erreur d'authentification.";
    }
}

require __DIR__ . '/inc/layout.php';
lay_head('Espace gérant');
?>
<section>
  <h1>Espace gérant — connexion</h1>
  <p>Réservé au personnel ShopXpress (gestion du back-office).</p>
  <?php if ($err): ?><div class="err"><?= htmlspecialchars($err) ?></div><?php endif; ?>
  <form class="box" method="post" action="/connexion.php">
    <label for="user">Identifiant</label>
    <input type="text" id="user" name="user" placeholder="ex. s.morel" autofocus>
    <label for="pass">Mot de passe</label>
    <input type="password" id="pass" name="pass">
    <button class="btn" type="submit" style="margin-top:16px">Se connecter</button>
  </form>
  <p class="note">Mot de passe oublié&nbsp;? Contactez l'administrateur (j.martin).</p>
</section>
<?php lay_foot(); ?>
