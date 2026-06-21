/* backoffice-check — vérificateur du mot de passe maître du BACK-OFFICE ShopXpress.
 *
 * CHALLENGE REVERSE (lab CTF) : le mot de passe maître attendu n'est PAS en
 * clair dans le binaire — il est stocké XORé (clé 0x5b). Le joueur doit lire le
 * binaire (Ghidra / objdump / ltrace) pour comprendre la vérification, retrouver
 * la clé 0x5b et déXORer le tableau `enc[]` → mot de passe maître.
 *
 * Si le mot de passe est correct, le binaire (SUID root) lit et affiche le
 * trophée final `/opt/shopxpress/trophy` (= accès back-office / compromission).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* mot de passe maître, XORé octet à octet avec la clé ci-dessous.
 * (enc[i] ^ 0x5b) = "ShopXpress-Adm-2024" */
static const unsigned char enc[] = {
    0x08,0x33,0x34,0x2b,0x03,0x2b,0x29,0x3e,0x28,0x28,
    0x76,0x1a,0x3f,0x36,0x76,0x69,0x6b,0x69,0x6f
};
static const unsigned char KEY = 0x5b;

int main(void)
{
    char in[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Mot de passe maitre (back-office ShopXpress) : ");
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

    FILE *f = fopen("/opt/shopxpress/trophy", "r");
    if (!f) {
        puts("Trophee introuvable.");
        return 1;
    }
    printf("Acces back-office accorde (compromission complete).\n");
    char line[256];
    while (fgets(line, sizeof(line), f))
        fputs(line, stdout);
    fclose(f);
    return 0;
}
