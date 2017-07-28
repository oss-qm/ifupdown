#define _GNU_SOURCE

#include <stdio.h>
#include <strings.h>
#include <err.h>
#include <fnmatch.h>
#include <net/if.h>
#include <net/if_dl.h>

#include "archcommon.h"

static bool match_mac(const char *iface, const char *pattern) {
	for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		struct sockaddr_dl *dl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (dl->sdl_alen != 6)
			continue;

		if (strcmp(ifa->ifa_name, iface))
			continue;

		unsigned char *ll = (unsigned char *)LLADDR(dl);
		char buf[18];
		snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", ll[0], ll[1], ll[2], ll[3], ll[4], ll[5]);
		return fnmatch(pattern, buf, FNM_EXTMATCH) == 0;
	}

	return false;
}

bool variable_match(const char *iface, const char *variable, const char *pattern) {
	if (!strcasecmp(variable, "mac"))
		return match_mac(iface, pattern);

	if (!strcasecmp(variable, "name"))
		return fnmatch(pattern, iface, FNM_EXTMATCH) == 0;

	warnx("Unknown or unsupported pattern variable %s", variable);
	return false;
}
