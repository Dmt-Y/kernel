/*
 *  fs/cifs/dns_resolve.c
 *
 *   Copyright (c) 2007 Igor Mammedov
 *   Author(s): Igor Mammedov (niallain@gmail.com)
 *              Steve French (sfrench@us.ibm.com)
 *              Wang Lei (wang840925@gmail.com)
 *		David Howells (dhowells@redhat.com)
 *
 *   Contains the CIFS DFS upcall routines used for hostname to
 *   IP address translation.
 *
 *   This library is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU Lesser General Public License as published
 *   by the Free Software Foundation; either version 2.1 of the License, or
 *   (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this library; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/dns_resolver.h>
#include "dns_resolve.h"
#include "cifsglob.h"
#include "cifsproto.h"
#include "cifs_debug.h"

/**
 * dns_resolve_server_name_to_ip - Resolve UNC server name to ip address.
 * @unc: UNC path specifying the server (with '/' as delimiter)
 * @ip_addr: Where to return the IP address.
 * @expiry: Where to return the expiry time for the dns record.
 *
 * Returns zero success, -ve on error.
 */
int
dns_resolve_server_name_to_ip(const char *unc, struct sockaddr *ip_addr, time64_t *expiry)
{
	const char *hostname, *sep;
	char *ip;
	int len, rc;

	if (!ip_addr || !unc)
		return -EINVAL;

	len = strlen(unc);
	if (len < 3) {
		cifs_dbg(FYI, "%s: unc is too short: %s\n", __func__, unc);
		return -EINVAL;
	}

	/* Discount leading slashes for cifs */
	len -= 2;
	hostname = unc + 2;

	/* Search for server name delimiter */
	sep = memchr(hostname, '/', len);
	if (sep)
		len = sep - hostname;
	else
		cifs_dbg(FYI, "%s: probably server name is whole unc: %s\n",
			 __func__, unc);

	/* Try to interpret hostname as an IPv4 or IPv6 address */
	rc = cifs_convert_address(ip_addr, hostname, len);
	if (rc > 0) {
		cifs_dbg(FYI, "%s: unc is IP, skipping dns upcall: %*.*s\n", __func__, len, len,
			 hostname);
		return 0;
	}

	/* Perform the upcall */
	rc = dns_query(NULL, hostname, len, NULL, &ip, expiry);
	if (rc < 0) {
		cifs_dbg(FYI, "%s: unable to resolve: %*.*s\n",
			 __func__, len, len, hostname);
	} else {
		cifs_dbg(FYI, "%s: resolved: %*.*s to %s expiry %llu\n",
			 __func__, len, len, hostname, ip,
			 expiry ? (*expiry) : 0);
		rc = cifs_convert_address(ip_addr, ip, strlen(ip));
		kfree(ip);

		if (!rc) {
			cifs_dbg(FYI, "%s: unable to determine ip address\n", __func__);
			rc = -EHOSTUNREACH;
		} else
			rc = 0;
	}
	return rc;
}
