#include "i18n.h"
#include "tm.h"

static const char *const MSG_EN[] = {
#define X(id, en, pt) en,
    TM_MESSAGES(X)
#undef X
};

static const char *const MSG_PT[] = {
#define X(id, en, pt) pt,
    TM_MESSAGES(X)
#undef X
};

static bool g_pt = false;

void i18n_set_lang(const char *lang)
{
    g_pt = lang && tm_strnicmp(lang, "pt", 2) == 0;
}

const char *i18n_lang(void)
{
    return g_pt ? "pt" : "en";
}

const char *T(tm_msg id)
{
    if ((unsigned)id >= M__COUNT) return "";
    return g_pt ? MSG_PT[id] : MSG_EN[id];
}
