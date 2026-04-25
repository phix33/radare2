/* radare - MIT - Copyright 2024-2026 - pancake */

// R2R db/cmd/newprj

#define R_LOG_ORIGIN "prj"

#include <r_core.h>
#include "newprj/newprj.h"
#include "newprj/format.inc.c"
#include "newprj/save.inc.c"
#include "newprj/load.inc.c"

static void prjhelp(void) {
	R_LOG_INFO ("prj save [file]   - save current state into a project file");
	R_LOG_INFO ("prj info [file]   - show information about the project file");
	R_LOG_INFO ("prj load [file]   - merge project information into the current session");
	R_LOG_INFO ("prj open [file]   - close current session and open the project from scratch");
	R_LOG_INFO ("prj diff [file]   - print commands for differences from file to current session");
	R_LOG_INFO ("prj r2 [file]     - print an r2 script for parsing purposes");
}

static void prjcmd(RCore *core, const char *mod, const char *arg) {
	if (arg) {
		char *argstr = strdup (arg);
		char *arg2 = strchr (argstr, ' ');
		if (arg2) {
			*arg2 = 0;
			arg2 = (char *)r_str_trim_head_ro (arg2 + 1);
		}
		if (arg2) {
			if (!strcmp (argstr, "save")) {
				r_core_newprj_save (core, arg2);
			} else if (!strcmp (argstr, "load")) {
				r_core_newprj_load (core, arg2, R_CORE_NEWPRJ_MODE_LOAD | R_CORE_NEWPRJ_MODE_CMD);
			} else if (!strcmp (argstr, "open")) {
				r_core_newprj_open (core, arg2);
			} else if (!strcmp (argstr, "r2")) {
				r_core_newprj_load (core, arg2, R_CORE_NEWPRJ_MODE_SCRIPT);
			} else if (!strcmp (argstr, "info")) {
				r_core_newprj_load (core, arg2, R_CORE_NEWPRJ_MODE_LOG);
			} else if (!strcmp (argstr, "diff")) {
				r_core_newprj_load (core, arg2, R_CORE_NEWPRJ_MODE_DIFF);
			}
		} else {
			prjhelp ();
		}
		free (argstr);
	} else {
		prjhelp ();
	}
}

static bool callback(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	if (r_str_startswith (input, "prj")) {
		const char *mod = input + 3;
		const char *arg = strchr (mod, ' ');
		if (*mod == ' ') {
			mod = NULL;
		}
		if (arg) {
			arg = r_str_trim_head_ro (arg + 1);
		}
		prjcmd (core, mod, arg);
		return true;
	}
	return false;
}

static bool plugin_init(RCorePluginSession *cps) {
	RCore *core = cps->core;
	if (!core || !core->autocomplete) {
		return true;
	}
	if (r_core_autocomplete_find (core->autocomplete, "prj", true)) {
		return true;
	}
	RCoreAutocomplete *root = r_core_autocomplete_add (core->autocomplete, "prj", R_CORE_AUTOCMPLT_DFLT, true);
	if (!root) {
		return true;
	}
	const char *subs[] = { "save", "load", "open", "info", "diff", "r2", NULL };
	int i;
	for (i = 0; subs[i]; i++) {
		r_core_autocomplete_add (root, subs[i], R_CORE_AUTOCMPLT_FILE, true);
	}
	return true;
}

static bool plugin_fini(RCorePluginSession *cps) {
	RCore *core = cps->core;
	if (core && core->autocomplete) {
		r_core_autocomplete_remove (core->autocomplete, "prj");
	}
	return true;
}

RCorePlugin r_core_plugin_prj = {
	.meta = {
		.name = "prj",
		.desc = "Experimental binary projects",
		.author = "pancake",
		.license = "MIT",
	},
	.init = plugin_init,
	.fini = plugin_fini,
	.call = callback,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_prj,
	.version = R2_VERSION
};
#endif
