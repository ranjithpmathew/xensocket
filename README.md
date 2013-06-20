xensocket
=========
/* xensocket.h
 *
 * Header file for shared-memory sockets transport for communications
 * between two domains on the same machine, under the Xen hypervisor.
 *
 * Authors: Xiaolan (Catherine) Zhang <cxzhang@us.ibm.com>
 *          Suzanne McIntosh <skranjac@us.ibm.com>
 *          John Griffin
 *
 * History:   
 *          Suzanne McIntosh    13-Aug-07     Initial open source version
 *
 * Copyright (c) 2007, IBM Corporation
 *
 */

#ifndef __XENSOCKET_H__
#define __XENSOCKET_H__

struct sockaddr_xe {
  sa_family_t sxe_family;
  u_int16_t   remote_domid;
  int         shared_page_gref;
};

#define AF_XEN  21
#define PF_XEN  AF_XEN

#define xen_sk(__sk) ((struct xen_sock *)__sk)

#endif /* __XENSOCKET_H__ */
