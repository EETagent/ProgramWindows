#include <stdbool.h>
#include <string.h>
#include <mongoose.h>

static const char *adresa = "http://0.0.0.0:80";

static char orders[100];

// Deklarace funkcí
static bool autorizace(struct mg_http_message *hm);
static bool autorizace(struct mg_http_message *hm);

// Aktualizace hodnot
static int aktualizce(struct mg_http_message *hm) {
    if (autorizace(hm) == true) {
        strncpy(hm->body.ptr, orders, len(orders));
    }
    return 0;
}

// Autorizace požadavků POST
static bool autorizace(struct mg_http_message *hm) {
    char uzivatel[1], heslo[256], *env_heslo;
    mg_http_creds(hm, uzivatel, sizeof(uzivatel), heslo, sizeof(heslo));
    if(getenv("HESLO") != NULL)
        env_heslo = getenv("HESLO");
    else
        // Naprosto bezpečné :)
        env_heslo = "heslo";
    return strcmp(heslo, env_heslo) == 0;
}

static void webserver(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev == MG_EV_HTTP_MSG) {
        // HTTP Požadavek
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        // 2K API
        if (mg_http_match_uri(hm, "/orders")) {
            if (strstr(hm->method.ptr, "POST") != NULL)
                aktualizce(hm);
            mg_http_reply(c, 200, "", "%s", orders);
        }
        // Webová aplikace
        else {
            struct mg_http_serve_opts opts = {.root_dir = "./public"};
            mg_http_serve_dir(c, ev_data, &opts);
        }
    }
    (void) fn_data;
}

int main(void) {
    struct mg_mgr http_server;

    // Inicializace webového serveru
    mg_mgr_init(&http_server);
    mg_http_listen(&http_server, adresa, webserver, NULL);

    // Nekonečná smyčka dokud nebude přerušena
    for (;;)
        mg_mgr_poll(&http_server, 1000);

    mg_mgr_free(&http_server);
    return 0;
}