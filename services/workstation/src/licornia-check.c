/* licornia-check — vérificateur du mot de passe maître de l'annuaire.
 *
 * CHALLENGE REVERSE (lab CTF) : le mot de passe maître attendu n'est PAS en
 * clair dans le binaire — il est stocké XORé (clé 0x5b). Le joueur doit lire le
 * binaire (Ghidra / objdump / ltrace) pour comprendre la vérification, retrouver
 * la clé 0x5b et déXORer le tableau `enc[]` → mot de passe maître.
 *
 * Si le mot de passe est correct, le binaire (SUID root) lit et affiche le
 * trophée final `/opt/licornia/trophy` (= prise du domaine).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* mot de passe maître, XORé octet à octet avec la clé ci-dessous. */
static const unsigned char enc[] = {
    0x2f,0x2c,0x32,0x37,0x32,0x3c,0x33,0x2f,0x76,0x28,
    0x2b,0x3a,0x29,0x30,0x37,0x3e,0x76,0x6f,0x69
};
static const unsigned char KEY = 0x5b;

int main(void)
{
    char in[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Mot de passe maitre (annuaire Licornia) : ");
    if (!fgets(in, sizeof(in), stdin))
        return 1;
    in[strcspn(in, "\r\n")] = '\0';

    size_t n = strlen(in);
    if (n != sizeof(enc)) {
        puts("Refuse.");
        return 1;
    }
    for (size_t i = 0; i < sizeof(enc); i++) {
        if ((unsigned char)(in[i] ^ KEY) != enc[i]) {
            puts("Refuse.");
            return 1;
        }
    }

    FILE *f = fopen("/opt/licornia/trophy", "r");
    if (!f) {
        puts("Trophee introuvable.");
        return 1;
    }
    printf("Acces annuaire accorde (prise du domaine).\n");
    char line[256];
    while (fgets(line, sizeof(line), f))
        fputs(line, stdout);
    fclose(f);
    return 0;
}
