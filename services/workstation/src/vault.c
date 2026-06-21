/* vault — coffre de la machine admin (ShopXpress).
 *
 * VULN INTENTIONNELLE (lab CTF) : débordement de tampon sur la pile.
 *   - `read()` lit jusqu'à 256 octets dans un tampon de 64 → écrasement de
 *     l'adresse de retour sauvegardée (ret2win).
 *   - compilé sans canari (-fno-stack-protector) et sans PIE (-no-pie) →
 *     adresses fixes, fonction win() à adresse connue (objdump/nm).
 *
 * Objectif joueur : faire retourner main() dans win() → shell root (SUID root).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void)
{
    /* Gagné : on devient root puis on ouvre un shell.
     * execve (et non system) : pas de souci d'alignement de pile movaps. */
    setuid(0);
    setgid(0);
    char *argv[] = { "/bin/sh", NULL };
    execve("/bin/sh", argv, NULL);
    _exit(0);
}

int main(void)
{
    char buf[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== Coffre ShopXpress (vault) ===");
    puts("Entrez le code d'acces du coffre :");
    read(0, buf, 0x100);              /* VULN : 256 octets dans 64 */
    printf("Code refuse: %s\n", buf);
    return 0;
}
