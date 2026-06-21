<?php require __DIR__ . '/inc/layout.php'; lay_head('Accueil'); ?>
<section class="hero">
  <h1>Bienvenue au Licornia Parc</h1>
  <p>Le parc à licornes préféré de la région&nbsp;: spectacles, balades arc-en-ciel
     et goûters enchantés. Ce portail est réservé au <strong>personnel</strong>.</p>
</section>

<section class="cards">
  <div class="card">
    <h2>🎠 Espace visiteurs</h2>
    <p>Billetterie et horaires (bientôt disponible).</p>
  </div>
  <div class="card">
    <h2>👩‍💼 Notre équipe</h2>
    <p>Retrouvez les membres du personnel du parc.</p>
    <a class="btn" href="/equipe.php">Voir l'équipe</a>
  </div>
  <div class="card">
    <h2>🛠️ Diagnostic réseau</h2>
    <p>Outil interne&nbsp;: tester la connectivité d'une machine du parc.</p>
    <a class="btn" href="/outils.php">Ouvrir l'outil</a>
  </div>
</section>
<?php lay_foot(); ?>
