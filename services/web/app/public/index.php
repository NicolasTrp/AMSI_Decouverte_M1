<?php require __DIR__ . '/inc/layout.php'; lay_head('Accueil'); ?>
<section class="hero">
  <h1>ShopXpress — votre boutique high-tech</h1>
  <p>Les meilleurs accessoires connectés, livrés en 24h. Profitez de nos
     promotions du moment et payez en toute sécurité.</p>
  <a class="btn" href="/produits.php">Voir le catalogue</a>
</section>

<section class="cards">
  <div class="card">
    <h2>🎧 Casque audio X200</h2>
    <p>Réduction de bruit active, autonomie 30h.</p>
    <p class="price">79,90 €</p>
  </div>
  <div class="card">
    <h2>⌚ Montre connectée FitPro</h2>
    <p>Suivi d'activité, GPS, étanche.</p>
    <p class="price">129,00 €</p>
  </div>
  <div class="card">
    <h2>🔌 Chargeur rapide 65W</h2>
    <p>Compatible USB-C, charge 3 appareils.</p>
    <p class="price">24,90 €</p>
  </div>
</section>

<section style="margin-top:24px">
  <p class="note">Besoin d'un justificatif&nbsp;? Retrouvez et téléchargez vos
     factures depuis <a href="/telecharger.php">votre espace factures</a>.</p>
</section>
<?php lay_foot(); ?>
