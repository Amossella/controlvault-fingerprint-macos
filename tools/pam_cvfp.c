/*
 * pam_cvfp.so — modulo PAM "auth" per impronta ControlVault.
 *
 * Lancia l'helper fpauth.py: se esce 0 (dito riconosciuto) -> PAM_SUCCESS,
 * altrimenti PAM_AUTH_ERR (PAM prosegue con la riga successiva = password).
 * Va messo come:  auth  sufficient  /usr/local/lib/pam_cvfp.so
 * PRIMA della riga della password, cosi' l'impronta e' opzionale e la
 * password resta sempre come fallback.
 *
 * Compila (lo fa install.sh), indicando dove si trova l'helper:
 *   clang -bundle -o pam_cvfp.so pam_cvfp.c -lpam \
 *         -DHELPER='"/percorso/del/progetto/tools/fpauth.py"'
 *   (opzionale: -DPY='"/percorso/python3"')
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#ifndef PY
#define PY     "/usr/local/bin/python3"
#endif
#ifndef HELPER
#error "definisci HELPER: -DHELPER='\"/percorso/tools/fpauth.py\"'"
#endif
#define TIMEOUT "12"              /* default; sovrascrivibile con un arg nel pam.d */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *user = NULL;
    const char *timeout = TIMEOUT;
    (void)flags;
    /* primo argomento nel pam.d (se numerico) = timeout in secondi */
    if (argc >= 1 && argv[0] && argv[0][0] >= '0' && argv[0][0] <= '9')
        timeout = argv[0];
    pam_get_user(pamh, &user, NULL);
    if (user == NULL) user = "";

    pid_t pid = fork();
    if (pid < 0) {
        return PAM_AUTH_ERR;        /* non blocca: cade sulla password */
    }
    if (pid == 0) {
        /* figlio: esegue l'helper; stderr ereditato -> messaggi nel prompt sudo */
        execl(PY, PY, HELPER, "--timeout", timeout, "--user", user, (char *)NULL);
        _exit(127);                 /* exec fallita */
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        /* ritenta su EINTR */
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return PAM_SUCCESS;          /* impronta riconosciuta */
    return PAM_AUTH_ERR;             /* -> prosegue con la password */
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
