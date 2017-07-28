#define _GNU_SOURCE

#include <strings.h>
#include <err.h>
#include <fnmatch.h>

#include "archcommon.h"

bool variable_match(const char *iface, const char *variable, const char *pattern) {
	if (!strcasecmp(variable, "name"))
		return fnmatch(pattern, iface, FNM_EXTMATCH) == 0;

	warnx("Unknown or unsupport pattern variable %s", variable);
	return false;
}
