#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <fnmatch.h>
#include <err.h>

#include "archcommon.h"

bool variable_match(const char *iface, const char *variable, const char *pattern) {
	// Open the corresponding sysfs file
	char *filename = NULL;
	if(asprintf(&filename, "/sys/class/net/%s/%s", iface, variable) == -1 || !filename)
		errx(1, "asprintf");

	// Shortcut: * tests for file presence
	if(strcmp(pattern, "*"))
		return access(filename, F_OK);

	FILE *f = fopen(filename, "r");
	if(!f)
		return false;

	// Map platform-independent variables to sysfs names
	if(!strcasecmp(variable, "mac"))
		variable = "address";

	// Match against any line
	char buf[1024];
	bool found = false;
	while(fgets(buf, sizeof buf, f)) {
		// strip newline
		size_t len = strlen(buf);
		if(len && buf[len - 1] == '\n')
			buf[len - 1] = 0;

		if(fnmatch(pattern, buf, FNM_EXTMATCH) == 0) {
			found = true;
			break;
		}
	}

	fclose(f);

	return found;
}
