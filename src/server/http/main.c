#include <stdbool.h>
#include <string.h>
#include <mongoose.h>

static const char *host = "http://0.0.0.0:80";

static char orders[100];

// Deklarace funkcí
static int refresh(struct mg_http_message *hm);
static int upload(struct mg_connection *c, struct mg_http_message* hm);
static bool autorization(struct mg_http_message *hm);

// Aktualizace hodnot
static int refresh(struct mg_http_message *hm) {
    if (autorization(hm) == true) {
        strncpy(orders, hm->body.ptr, sizeof(orders));
        return 0;
    }
    return 1;
}

// Upload hodnot
static int upload(struct mg_connection* c, struct mg_http_message* hm) {
    if (autorization(hm) == true) {
        mg_http_upload(c, hm, "/public");
        return 0;
    }
    return 1;
}

// Autorizace požadavků POST
static bool autorization(struct mg_http_message *hm) {
    char user[1], password[256], *env_password;
    mg_http_creds(hm, user, sizeof(user), password, sizeof(password));
    if(getenv("HESLO") != NULL)
        env_password = getenv("HESLO");
    else
        // Naprosto bezpečné :)
        env_password = "heslo";
    return strcmp(password, env_password) == 0;
}

static void webserver(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev == MG_EV_HTTP_MSG) {
        // HTTP Požadavek
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        // Rozkazy API
        if (mg_http_match_uri(hm, "/orders")) {
            if (strstr(hm->method.ptr, "POST") != NULL)
                refresh(hm);
            mg_http_reply(c, 200, "", "%s", orders);
        }
        // Payload API
        if (mg_http_match_uri(hm, "/payloads")) {
            if (strstr(hm->method.ptr, "POST") != NULL)
                upload(c, hm);
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
    mg_http_listen(&http_server, host, webserver, NULL);

    // Nekonečná smyčka dokud nebude přerušena
    for (;;)
        mg_mgr_poll(&http_server, 1000);

    mg_mgr_free(&http_server);
    return 0;
}