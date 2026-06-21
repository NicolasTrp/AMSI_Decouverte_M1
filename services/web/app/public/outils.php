<?php
require __DIR__ . '/inc/layout.php';

// ⚠️ VULN INTENTIONNELLE (lab CTF) : la saisie utilisateur est concaténée telle
// quelle dans une commande shell → INJECTION DE COMMANDE.
// Bonne pratique (non appliquée ici exprès) : escapeshellarg() + liste blanche.
$host = isset($_GET['host']) ? $_GET['host'] : '';
$output = '';
if ($host !== '') {
    $output = shell_exec("ping -c 2 " . $host . " 2>&1");
}

lay_head('Diagnostic réseau');
?>
<section>
  <h1>Diagnostic réseau interne</h1>
  <p>Outil de maintenance&nbsp;: vérifier qu'une machine du parc répond au ping.</p>

  <form method="get" action="/outils.php">
    <input type="text" name="host" value="<?= htmlspecialchars($host) ?>"
           placeholder="ex. 127.0.0.1 ou files.licornia.lan" autofocus>
    <button type="submit">Tester</button>
  </form>

  <?php if ($host !== ''): ?>
    <h2>Résultat</h2>
    <pre class="term"><?= htmlspecialchars($output) ?></pre>
  <?php endif; ?>

  <p class="note">Astuce maintenance&nbsp;: l'outil accepte un nom d'hôte ou une IP.</p>
</section>
<?php lay_foot(); ?>
