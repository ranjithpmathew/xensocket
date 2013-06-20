/* xensocket.c
 *
 * XVMSocket module for a shared-memory sockets transport for communications
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

#include <linux/module.h>
#include <linux/kernel.h>

#include <net/sock.h>
#include <net/tcp_states.h>

#include <xen/driver_util.h>
#include <xen/gnttab.h>
#include <xen/evtchn.h>

#include "xensocket.h"

#define DPRINTK( x, args... ) printk(KERN_CRIT "%s: line %d: " x, __FUNCTION__ , __LINE__ , ## args ); 

#define DEBUG
#ifdef DEBUG
#define TRACE_ENTRY printk(KERN_CRIT "Entering %s\n", __func__)
#define TRACE_EXIT  printk(KERN_CRIT "Exiting %s\n", __func__)
#else
#define TRACE_ENTRY do {} while (0)
#define TRACE_EXIT  do {} while (0)
#endif
#define TRACE_ERROR printk(KERN_CRIT "Exiting (ERROR) %s\n", __func__)

/* ++++++++++++++++++++++++++++++++++++++++++++ */
#define CM_SET_GREF  0x01
#define CM_GET_GREF	0x02
#define CM_FREE_NODE	0x03
typedef struct{
	u_int16_t   remote_domid;
  	int         shared_page_gref;
}SHARE_PAGE_GREF;
/* +++++++++++++++++++++++++++++++++++++++++++ */

struct descriptor_page;
struct xen_sock;

static void
initialize_descriptor_page (struct descriptor_page *d);

static void
initialize_xen_sock (struct xen_sock *x);

static int
xen_create (struct socket *sock, int protocol);

static int
xen_bind (struct socket *sock, struct sockaddr *uaddr, int addr_len);

static int
server_allocate_descriptor_page (struct xen_sock *x);

static int
server_allocate_event_channel (struct xen_sock *x);

static int
server_allocate_buffer_pages (struct xen_sock *x);

static int
xen_connect (struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags);

static int
client_map_descriptor_page (struct xen_sock *x);

static int
client_bind_event_channel (struct xen_sock *x);

static int
client_map_buffer_pages (struct xen_sock *x);

static int
xen_sendmsg (struct kiocb *kiocb, struct socket *sock, struct msghdr *msg, size_t len);

static inline int
is_writeable (struct descriptor_page *d);

static long
send_data_wait (struct sock *sk, long timeo);

static irqreturn_t
client_interrupt (int irq, void *dev_id, struct pt_regs *regs);

static int
xen_recvmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t size, int flags);

static inline int
is_readable (struct descriptor_page *d);

static long
receive_data_wait (struct sock *sk, long timeo);

static irqreturn_t
server_interrupt (int irq, void *dev_id, struct pt_regs *regs);

static int
local_memcpy_toiovecend (struct iovec *iov, unsigned char *kdata, int offset, int len);

static int
xen_release (struct socket *sock);

static int
xen_shutdown (struct socket *sock, int how);

static void
server_unallocate_buffer_pages (struct xen_sock *x);

static void
server_unallocate_descriptor_page (struct xen_sock *x);

static void
client_unmap_buffer_pages (struct xen_sock *x);

static void
client_unmap_descriptor_page (struct xen_sock *x);

static int __init
xensocket_init (void);

static void __exit
xensocket_exit (void);

/************************************************************************
 * Data structures for internal recordkeeping and shared memory.
 ************************************************************************/

struct descriptor_page {
  uint32_t        server_evtchn_port;
  int             buffer_order; /* num_pages = (1 << buffer_order) */
  int             buffer_first_gref;
  unsigned int    send_offset;
  unsigned int    recv_offset;
  unsigned int    total_bytes_sent;
  unsigned int    total_bytes_received;
  unsigned int    sender_is_blocking;
  atomic_t        avail_bytes;
  atomic_t        sender_has_shutdown;
  atomic_t        force_sender_shutdown;
};

static void
initialize_descriptor_page (struct descriptor_page *d)
{
  d->server_evtchn_port = -1;
  d->buffer_order = -1;
  d->buffer_first_gref = -ENOSPC;
  d->send_offset = 0;
  d->recv_offset = 0;
  d->total_bytes_sent = 0;
  d->total_bytes_received = 0;
  d->sender_is_blocking = 0;
  atomic_set(&d->avail_bytes, 0);
  atomic_set(&d->sender_has_shutdown, 0);
  atomic_set(&d->force_sender_shutdown, 0);
}

/* struct xen_sock:
 *
 * @sk: this must be the first element in the structure.
 */
struct xen_sock {
  struct sock             sk;
  unsigned char           is_server, is_client;
  domid_t                 otherend_id;
  struct descriptor_page *descriptor_addr;    /* server and client */
  int                     descriptor_gref;    /* server only */
  struct vm_struct       *descriptor_area;    /* client only */
  grant_handle_t          descriptor_handle;  /* client only */
  unsigned int            evtchn_local_port;
  unsigned int            irq;
  unsigned long           buffer_addr;    /* server and client */
  int                    *buffer_grefs;   /* server */
  struct vm_struct       *buffer_area;    /* client */
  grant_handle_t         *buffer_handles; /* client */
  int                     buffer_order;
};

static void
initialize_xen_sock (struct xen_sock *x) {
  x->is_server = 0;
  x->is_client = 0;
  x->otherend_id = -1;
  x->descriptor_addr = NULL;
  x->descriptor_gref = -ENOSPC;
  x->descriptor_area = NULL;
  x->descriptor_handle = -1;
  x->evtchn_local_port = -1;
  x->irq = -1;
  x->buffer_addr = 0;
  x->buffer_area = NULL;
  x->buffer_handles = NULL;
  x->buffer_order = -1;
}

static struct proto xen_proto = {
  .name           = "XEN",
  .owner          = THIS_MODULE,
  .obj_size       = sizeof(struct xen_sock),
};

static const struct proto_ops xen_stream_ops = {
  .family         = AF_XEN,
  .owner          = THIS_MODULE,
  .release        = xen_release,
  .bind           = xen_bind,
  .connect        = xen_connect,
  .socketpair     = sock_no_socketpair,
  .accept         = sock_no_accept,
  .getname        = sock_no_getname,
  .poll           = sock_no_poll,
  .ioctl          = sock_no_ioctl,
  .listen         = sock_no_listen,
  .shutdown       = xen_shutdown,
  .getsockopt     = sock_no_getsockopt,
  .setsockopt     = sock_no_setsockopt,
  .sendmsg        = xen_sendmsg,
  .recvmsg        = xen_recvmsg,
  .mmap           = sock_no_mmap,
  .sendpage       = sock_no_sendpage,
};

static struct net_proto_family xen_family_ops = {
  .family         = AF_XEN,
  .create         = xen_create,
  .owner          = THIS_MODULE,
};

static int
xen_shutdown (struct socket *sock, int how) {
  struct sock *sk = sock->sk;
  struct xen_sock *x;
  struct descriptor_page *d;
  SHARE_PAGE_GREF hypercall_arg;
  x = xen_sk(sk);
  d = x->descriptor_addr;

  if (x->is_server) {
/* +++++++++++++++++++++++++++++++++++++++++++ */
    hypercall_arg.remote_domid = x->otherend_id;
    hypercall_arg.shared_page_gref = -1;
    if ( _hypercall2(long, myhpcall_gref_handler, CM_FREE_NODE, &hypercall_arg) )
    {
        DPRINTK("ERR: free node failed.\n");
    }
/* +++++++++++++++++++++++++++++++++++++++++++ */
    atomic_set(&d->force_sender_shutdown, 1);
  }

  return xen_release(sock);
}

/************************************************************************
 * Socket initialization (common to both server and client code).
 *
 * When a user-level program calls socket(), the xen_create() function
 * is called to set up the local structures (struct sock) that describe
 * the socket.  Our treatment of this is currently simple; there are a
 * lot of components of the sock structure that we do not use.  For
 * comparison, see the function unix_create in linux/net/unix/af_unix.c.
 ************************************************************************/

static int
xen_create (struct socket *sock, int protocol) {
  int    rc = 0;
  struct sock *sk;
  struct xen_sock *x;
 
  TRACE_ENTRY;

  sock->state = SS_UNCONNECTED;

  switch (sock->type) {
    case SOCK_STREAM:
      sock->ops = &xen_stream_ops;
      break;
    default:
      rc = -ESOCKTNOSUPPORT;
      goto out;
    }

  sk = sk_alloc(PF_XEN, GFP_KERNEL, &xen_proto, 1);
  if (!sk) {
    rc = -ENOMEM;
    goto out;
  }

  sock_init_data(sock, sk);
  sk->sk_family   = PF_XEN;
  sk->sk_protocol = protocol;
  x = xen_sk(sk);
  initialize_xen_sock(x);

out:
  TRACE_EXIT;
  return rc;
}

/************************************************************************
 * Server-side connection setup functions.
 ************************************************************************/

/* In our nonstandard use of the bind function, the return value is the
 * grant table entry of the descriptor page.
 */
static int
xen_bind (struct socket *sock, struct sockaddr *uaddr, int addr_len) {
  int    rc = -EINVAL;
  struct sock *sk = sock->sk;
  struct xen_sock *x = xen_sk(sk);
  struct sockaddr_xe *sxeaddr = (struct sockaddr_xe *)uaddr;
  SHARE_PAGE_GREF hypercall_arg;
  TRACE_ENTRY;

  if (sxeaddr->sxe_family != AF_XEN) {
    goto err;
  }

  /* Ensure that bind() is only called once for this socket.
   */

  if (x->is_server) {
    DPRINTK("error: cannot call bind() more than once on a socket\n");
    goto err;
  }
  if (x->is_client) {
    DPRINTK("error: cannot call both bind() and connect() on the same socket\n");
    goto err;
  }
  x->is_server = 1;

  x->otherend_id = sxeaddr->remote_domid;

  if ((rc = server_allocate_descriptor_page(x)) != 0) {
    goto err;
  }

  if ((rc = server_allocate_event_channel(x)) != 0) {
    goto err;
  }

  if ((rc = server_allocate_buffer_pages(x)) != 0) {
    goto err;
  }

  /* A successful function exit returns the grant table reference. */
  hypercall_arg.remote_domid = x->otherend_id;
  hypercall_arg.shared_page_gref = x->descriptor_gref;
  if ( _hypercall2(long, myhpcall_gref_handler, CM_SET_GREF, &hypercall_arg) )
  {
	DPRINTK("ERR: set gref failed.\n");
  }
  TRACE_EXIT;
  return x->descriptor_gref;

err:
  TRACE_ERROR;
  return rc;
}

static int
server_allocate_descriptor_page (struct xen_sock *x) {
  TRACE_ENTRY;

  if (x->descriptor_addr) {
    DPRINTK("error: already allocated server descriptor page\n");
    goto err;
  }

  if (!(x->descriptor_addr = (struct descriptor_page *)__get_free_page(GFP_KERNEL))) {
    DPRINTK("error: cannot allocate free page\n");
    goto err_unalloc;
  }

  initialize_descriptor_page(x->descriptor_addr);

  if ((x->descriptor_gref = gnttab_grant_foreign_access(x->otherend_id, virt_to_mfn(x->descriptor_addr), 0)) == -ENOSPC) {
    DPRINTK("error: cannot share descriptor page %p\n", x->descriptor_addr);
    goto err_unalloc;
  }

  TRACE_EXIT;
  return 0;

err_unalloc:
  server_unallocate_descriptor_page(x);

err:
  TRACE_ERROR;
  return -ENOMEM;
}

static int
server_allocate_event_channel (struct xen_sock *x) {
  //evtchn_op_t op;
  evtchn_alloc_unbound_t op;
  int         rc;

  TRACE_ENTRY;

  memset(&op, 0, sizeof(op));
  //op.cmd = EVTCHNOP_alloc_unbound;
  //op.u.alloc_unbound.dom = DOMID_SELF;
  //op.u.alloc_unbound.remote_dom = x->otherend_id;
  op.dom = DOMID_SELF;
  op.remote_dom = x->otherend_id;

  if ((rc = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op)) != 0) {
	DPRINTK("Unable to allocate event channel\n");
	goto err;
   }

  x->evtchn_local_port = op.port;
  x->descriptor_addr->server_evtchn_port = x->evtchn_local_port;

  /* Next bind this end of the event channel to our local callback
   * function. */

  if ((rc = bind_caller_port_to_irqhandler(x->evtchn_local_port, server_interrupt, SA_SAMPLE_RANDOM, "xensocket", x)) <= 0) {
    DPRINTK("Unable to bind event channel to irqhandler\n");
    goto err;
  }

  TRACE_EXIT;
  return 0;

err:
  TRACE_ERROR;
  return rc;
}

static int
server_allocate_buffer_pages (struct xen_sock *x) {
  struct descriptor_page *d = x->descriptor_addr;
  int    buffer_num_pages;
  int    i;

  TRACE_ENTRY;

  if (!d) {
    /* must call server_allocate_descriptor_page first */
    DPRINTK("error: descriptor page not yet allocated\n");
    goto err;
  }

  if (x->buffer_addr) {
    DPRINTK("error: already allocated server buffer pages\n");
    goto err;
  }

  x->buffer_order = 5;  //32 pages    /* you can change this as desired */
  buffer_num_pages = (1 << x->buffer_order);

  if (!(x->buffer_addr = __get_free_pages(GFP_KERNEL, x->buffer_order))) {
    DPRINTK("error: cannot allocate %d pages\n", buffer_num_pages);
    goto err;
  }

  if (!(x->buffer_grefs = kmalloc(buffer_num_pages * sizeof(int), GFP_KERNEL))) {
    DPRINTK("error: unexpected memory allocation failure\n");
    goto err_unallocate;
  } 
  else {
    /* Success, so first invalidate all the entries */
    for (i = 0; i < buffer_num_pages; i++) {
      x->buffer_grefs[i] = -ENOSPC;
    }
  }

  printk("x->buffer_addr = %lx  PAGE_SIZE = %li  buffer_num_pages = %d\n", x->buffer_addr, PAGE_SIZE, buffer_num_pages);
  for (i = 0; i < buffer_num_pages; i++) {
    if ((x->buffer_grefs[i] = gnttab_grant_foreign_access(x->otherend_id, virt_to_mfn(x->buffer_addr + i * PAGE_SIZE), 0)) == -ENOSPC) {
      DPRINTK("error: cannot share buffer page #%d\n", i);
      goto err_unallocate;
    }
  }

  /* In this scheme, we initially use each page to hold
   * the grant table reference for the next page.  The client maps
   * the next page by reading the gref from the current page.
   */

  d->buffer_first_gref = x->buffer_grefs[0];
  for (i = 1; i < buffer_num_pages; i++) {
    int *next_gref = (int *)(x->buffer_addr + (i-1) * PAGE_SIZE);
    *next_gref = x->buffer_grefs[i];
  }

  d->buffer_order = x->buffer_order;
  atomic_set(&d->avail_bytes, (1 << d->buffer_order) * PAGE_SIZE);

  TRACE_EXIT;
  return 0;

err_unallocate:
  server_unallocate_buffer_pages(x);

err:
  TRACE_ERROR;
  return -ENOMEM;
}

/************************************************************************
 * Client-side connection setup functions.
 ************************************************************************/

static int
xen_connect (struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags) {
  int    rc = -EINVAL;
  struct sock *sk = sock->sk;
  struct xen_sock *x = xen_sk(sk);
  struct sockaddr_xe *sxeaddr = (struct sockaddr_xe *)uaddr;
  SHARE_PAGE_GREF hypercall_arg;
  TRACE_ENTRY;

  if (sxeaddr->sxe_family != AF_XEN) {
    goto err;
  }

  /* Ensure that connect() is only called once for this socket.
   */

  if (x->is_client) {
    DPRINTK("error: cannot call connect() more than once on a socket\n");
    goto err;
  }
  if (x->is_server) {
    DPRINTK("error: cannot call both bind() and connect() on the same socket\n");
    goto err;
  }
  x->is_client = 1;

  x->otherend_id = sxeaddr->remote_domid;
  x->descriptor_gref = sxeaddr->shared_page_gref;

/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
  if( x->descriptor_gref <=0 )
 {
	DPRINTK("####get gref by hypercall.\n");
	hypercall_arg.remote_domid = sxeaddr->remote_domid;
  	hypercall_arg.shared_page_gref = -1;
  	if ( _hypercall2(long, myhpcall_gref_handler, CM_GET_GREF, &hypercall_arg) )
 	{
		DPRINTK("ERR: get gref failed.\n");
		goto err;
 	}
	x->descriptor_gref = hypercall_arg.shared_page_gref;
	DPRINTK("shared_page_gref = %d.\n", x->descriptor_gref);
 }
/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

  if ((rc = client_map_descriptor_page(x)) != 0) {
    goto err;
  }

  if ((rc = client_bind_event_channel(x)) != 0) {
    goto err_unmap_descriptor;
  }

  if ((rc = client_map_buffer_pages(x)) != 0) {
    goto err_unmap_buffer;
  }

  TRACE_EXIT;
  return 0;

err_unmap_buffer:
  client_unmap_buffer_pages(x);

err_unmap_descriptor:
  client_unmap_descriptor_page(x);
  notify_remote_via_evtchn(x->evtchn_local_port);

err:
  return rc;
}

static int
client_map_descriptor_page (struct xen_sock *x) {
  struct gnttab_map_grant_ref op;
  int    rc = -ENOMEM;

  TRACE_ENTRY;

  if (x->descriptor_addr) {
    DPRINTK("error: already allocated client descriptor page\n");
    goto err;
  }

  if ((x->descriptor_area = alloc_vm_area(PAGE_SIZE)) == NULL) {
    DPRINTK("error: cannot allocate memory for descriptor page\n");
    goto err;
  }

  x->descriptor_addr = x->descriptor_area->addr;

  memset(&op, 0, sizeof(op));
  op.host_addr = (unsigned long)x->descriptor_addr;
  op.flags = GNTMAP_host_map;
  op.ref = x->descriptor_gref;
  op.dom = x->otherend_id;

  //lock_vm_area(x->descriptor_area);
  rc = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1);
  //unlock_vm_area(x->descriptor_area);
  if (rc == -ENOSYS) {
    goto err_unmap;
  }

  if (op.status) {
    DPRINTK("error: grant table mapping operation failed\n");
    goto err_unmap;
  }

  x->descriptor_handle = op.handle;

  TRACE_EXIT;
  return 0;

err_unmap:
  client_unmap_descriptor_page(x);

err:
  TRACE_ERROR;
  return rc;
}

static int
client_bind_event_channel (struct xen_sock *x) {
  evtchn_bind_interdomain_t op;
  int         rc;

  TRACE_ENTRY;

  /* Start by binding this end of the event channel to the other
   * end of the event channel. */

  memset(&op, 0, sizeof(op));
  //op.cmd = EVTCHNOP_bind_interdomain;
  //op.u.bind_interdomain.remote_dom = x->otherend_id;
  //op.u.bind_interdomain.remote_port = x->descriptor_addr->server_evtchn_port;
  op.remote_dom = x->otherend_id;
  op.remote_port = x->descriptor_addr->server_evtchn_port;

  if ((rc = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain,&op)) != 0) {
	DPRINTK("Unable to bind to sender's event channel\n");
	goto err;
  }

  x->evtchn_local_port = op.local_port;

  DPRINTK("Other port is %d\n", x->descriptor_addr->server_evtchn_port);
  DPRINTK("My port is %d\n", op.local_port);

  /* Next bind this end of the event channel to our local callback
   * function. */
  if ((rc = bind_caller_port_to_irqhandler(x->evtchn_local_port, client_interrupt, SA_SAMPLE_RANDOM, "xensocket", x)) <= 0) {
    DPRINTK("Unable to bind event channel to irqhandler\n");
    goto err;
  }

  x->irq = rc;

  TRACE_EXIT;
  return 0;

err:
  TRACE_ERROR;
  return rc;
}

static int
client_map_buffer_pages (struct xen_sock *x) {
  struct descriptor_page *d = x->descriptor_addr;
  int    buffer_num_pages;
  int    *grefp;
  int    i;
  struct gnttab_map_grant_ref op;
  int    rc = -ENOMEM;

  TRACE_ENTRY;

  if (!d) {
    /* must call client_map_descriptor_page first */
    DPRINTK("error: descriptor page not yet mapped\n");
    goto err;
  }

  if (x->buffer_area) {
    DPRINTK("error: already allocated client buffer pages\n");
    goto err;
  }

  if (d->buffer_order == -1) {
    DPRINTK("error: server has not yet allocated buffer pages\n");
    goto err;
  }

  x->buffer_order = d->buffer_order;
  buffer_num_pages = (1 << x->buffer_order);

  if (!(x->buffer_handles = kmalloc(buffer_num_pages * sizeof(grant_handle_t), GFP_KERNEL))) {
    DPRINTK("error: unexpected memory allocation failure\n");
    goto err;
  } 
  else {
    for (i = 0; i < buffer_num_pages; i++) {
      x->buffer_handles[i] = -1;
    }
  }

  if (!(x->buffer_area = alloc_vm_area(buffer_num_pages * PAGE_SIZE))) {
    DPRINTK("error: cannot allocate %d buffer pages\n", buffer_num_pages);
    goto err_unmap;
  }

  x->buffer_addr = (unsigned long)x->buffer_area->addr;

  grefp = &d->buffer_first_gref;
  for (i = 0; i < buffer_num_pages; i++) {
    memset(&op, 0, sizeof(op));
    op.host_addr = x->buffer_addr + i * PAGE_SIZE;
    op.flags = GNTMAP_host_map;
    op.ref = *grefp;
    op.dom = x->otherend_id;

    //lock_vm_area(x->buffer_area);
    rc = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &op, 1);
    //unlock_vm_area(x->buffer_area);
    if (rc == -ENOSYS) {
      goto err_unmap;
    }

    if (op.status) {
      DPRINTK("error: grant table mapping failed\n");
      goto err_unmap;
    }

    x->buffer_handles[i] = op.handle;
    grefp = (int *)(x->buffer_addr + i * PAGE_SIZE);
  }

  TRACE_EXIT;
  return 0;

err_unmap:
  client_unmap_buffer_pages(x);

err:
  TRACE_ERROR;
  return rc;
}

/************************************************************************
 * Data transmission functions (client-only in a one-way communication
 * channel).
 ************************************************************************/

static int
xen_sendmsg (struct kiocb *kiocb, struct socket *sock, struct msghdr *msg, size_t len) {
  int                     rc = -EINVAL;
  struct sock            *sk = sock->sk;
  struct xen_sock        *x = xen_sk(sk);
  struct descriptor_page *d = x->descriptor_addr;
  unsigned int            max_offset = (1 << x->buffer_order) * PAGE_SIZE;
  long                    timeo;
  unsigned int            copied = 0;

  TRACE_ENTRY;

  timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);

  while (copied < len) {
    unsigned int send_offset = d->send_offset;
    unsigned int avail_bytes = atomic_read(&d->avail_bytes);
    unsigned int bytes;

    if (atomic_read(&d->force_sender_shutdown) != 0) {
      rc = xen_release(sock);
      goto err;
    }

    /* Determine the maximum amount that can be written */
    bytes = len - copied;
    bytes = min(bytes, avail_bytes);

    /* Block if no space is available */
    if (bytes == 0) {
      timeo = send_data_wait(sk, timeo);
      if (signal_pending(current)) {
        rc = sock_intr_errno(timeo);
        goto err;
      }
      continue;
    }

    if ((send_offset + bytes) > max_offset) {
      /* wrap around, need to copy twice */
      unsigned int bytes_segment1 = max_offset - send_offset;
      unsigned int bytes_segment2 = bytes - bytes_segment1;
      if (memcpy_fromiovecend((unsigned char *)(x->buffer_addr + send_offset), 
          msg->msg_iov, copied, bytes_segment1) == -EFAULT) {
        DPRINTK("error: copy_from_user failed\n");
        goto err;
      } 
      if (memcpy_fromiovecend((unsigned char *)(x->buffer_addr), 
          msg->msg_iov, copied + bytes_segment1, bytes_segment2) == -EFAULT) {
        DPRINTK("error: copy_from_user failed\n");
        goto err;
      }
    } 
	else {
      /* no need to wrap around */
      if (memcpy_fromiovecend((unsigned char *)(x->buffer_addr + send_offset), 
          msg->msg_iov, copied, bytes) == -EFAULT) {
        DPRINTK("error: copy_from_user failed\n");
        goto err;
      }
    }

    /* Update values */
    copied += bytes;
    d->send_offset = (send_offset + bytes) % max_offset;
    d->total_bytes_sent += bytes;
    atomic_sub(bytes, &d->avail_bytes);
  }
  
  notify_remote_via_evtchn(x->evtchn_local_port);

  TRACE_EXIT;
  return copied;

err:
  TRACE_ERROR;
  return copied; 
}

static inline int
is_writeable (struct descriptor_page *d) {
  unsigned int avail_bytes = atomic_read(&d->avail_bytes);
  if (avail_bytes > 0) 
    return 1;
	
  return 0;
}

static long
send_data_wait (struct sock *sk, long timeo) {
  struct xen_sock *x = xen_sk(sk);
  struct descriptor_page *d = x->descriptor_addr;
  DEFINE_WAIT(wait);

  TRACE_ENTRY;

  d->sender_is_blocking = 1;
  notify_remote_via_evtchn(x->evtchn_local_port);

  for (;;) {
    prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

    if (is_writeable(d)
        || !skb_queue_empty(&sk->sk_receive_queue)
        || sk->sk_err
        || (sk->sk_shutdown & RCV_SHUTDOWN)
        || signal_pending(current)
        || !timeo
        || atomic_read(&d->force_sender_shutdown)) {
      break;
    }

    timeo = schedule_timeout(timeo);
  }

  d->sender_is_blocking = 0;

  finish_wait(sk->sk_sleep, &wait);

  TRACE_EXIT;
  return timeo;
}

static irqreturn_t
client_interrupt (int irq, void *dev_id, struct pt_regs *regs) {
  struct xen_sock *x = dev_id;
  struct sock     *sk = &x->sk;

  TRACE_ENTRY;

  if (sk->sk_sleep && waitqueue_active(sk->sk_sleep)) {
    wake_up_interruptible(sk->sk_sleep);
  }

  TRACE_EXIT;
  return IRQ_HANDLED;
}

/************************************************************************
 * Data reception functions (server-only in a one-way communication
 * channel, but common to both in a two-way channel).
 ***********************************************************************/

static int
xen_recvmsg (struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t size, int flags) {
  int                     rc = -EINVAL;
  struct sock            *sk = sock->sk;
  struct xen_sock        *x = xen_sk(sk);
  struct descriptor_page *d = x->descriptor_addr;
  unsigned int            max_offset = (1 << x->buffer_order) * PAGE_SIZE;
  long                    timeo;
  int                     copied = 0;
  int                     target;

  TRACE_ENTRY;

  target = sock_rcvlowat(sk, flags&MSG_WAITALL, size);
  timeo = sock_rcvtimeo(sk, flags&MSG_DONTWAIT);

  while (copied < size) {
    unsigned int recv_offset = d->recv_offset;
    unsigned int bytes;
    unsigned int avail_bytes = max_offset - atomic_read(&d->avail_bytes);  /* bytes available for read */

    /* Determine the maximum amount that can be read */
    bytes = min(size - copied, avail_bytes);

    if (atomic_read(&d->sender_has_shutdown) != 0) {
      if (avail_bytes == 0) {
        copied = 0;
        break;
      }
    }

    /* Block if the buffer is empty */
    if (bytes == 0) {
      if (copied > target) {
        break;
      }

      timeo = receive_data_wait(sk, timeo);
      if (signal_pending(current)) {
        rc = sock_intr_errno(timeo);
        DPRINTK("error: signal\n");
        goto err;
      }
      continue;
    }

    /* Perform the read */
    if ((recv_offset + bytes) > max_offset) {
      /* wrap around, need to perform the read twice */
      unsigned int bytes_segment1 = max_offset - recv_offset;
      unsigned int bytes_segment2 = bytes - bytes_segment1;
      if (local_memcpy_toiovecend(msg->msg_iov, (unsigned char *)(x->buffer_addr + recv_offset), 
                                  copied, bytes_segment1) == -EFAULT) {
        DPRINTK("error: copy_to_user failed\n");
        goto err;
      }
      if (local_memcpy_toiovecend(msg->msg_iov, (unsigned char *)(x->buffer_addr), 
                                  copied + bytes_segment1, bytes_segment2) == -EFAULT) {
        DPRINTK("error: copy_to_user failed\n");
        goto err;
      }
    } 
	else {
      /* no wrap around, proceed with one copy */
      if (local_memcpy_toiovecend(msg->msg_iov, (unsigned char *)(x->buffer_addr + recv_offset), 
                                  copied, bytes) == -EFAULT) {
        DPRINTK("error: copy_to_user failed\n");
        goto err;
      }
    }

    /* Update values */
    copied += bytes;
    d->recv_offset = (recv_offset + bytes) % max_offset;
    d->total_bytes_received += bytes;
    atomic_add(bytes, &d->avail_bytes);
    if (d->sender_is_blocking) {
      notify_remote_via_evtchn(x->evtchn_local_port);
    }
  }

  TRACE_EXIT;
  return copied;

err:
  TRACE_ERROR;
  return copied;
}

static inline int
is_readable (struct descriptor_page *d) {
  unsigned int max_offset = (1 << d->buffer_order) * PAGE_SIZE;
  unsigned int avail_bytes = max_offset - atomic_read(&d->avail_bytes);
  if (avail_bytes > 0)
    return 1;

  return 0;
}

static long
receive_data_wait (struct sock *sk, long timeo) {
  struct xen_sock        *x = xen_sk(sk);
  struct descriptor_page *d = x->descriptor_addr;
  DEFINE_WAIT(wait);

  TRACE_ENTRY;

  for (;;) {
    prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
    if (is_readable(d)
        || (atomic_read(&d->sender_has_shutdown) != 0)
        || !skb_queue_empty(&sk->sk_receive_queue)
        || sk->sk_err
        || (sk->sk_shutdown & RCV_SHUTDOWN)
        || signal_pending(current)
        || !timeo) {
      break;
    }

    timeo = schedule_timeout(timeo);
  }

  finish_wait(sk->sk_sleep, &wait);

  TRACE_EXIT;
  return timeo;
}

static irqreturn_t
server_interrupt (int irq, void *dev_id, struct pt_regs *regs) {
  struct xen_sock *x = dev_id;
  struct sock     *sk = &x->sk;

  TRACE_ENTRY;

  if (sk->sk_sleep && waitqueue_active(sk->sk_sleep)) {
    wake_up_interruptible(sk->sk_sleep);
  }

  TRACE_EXIT;
  return IRQ_HANDLED;
}

static int
local_memcpy_toiovecend (struct iovec *iov, unsigned char *kdata, int offset, int len) {
  int err = -EFAULT; 

  /* Skip over the finished iovecs */
  while (offset >= iov->iov_len) {
    offset -= iov->iov_len;
    iov++;
  }

  while (len > 0) {
    u8 *base = iov->iov_base + offset;
    int copy = min((unsigned int)len, iov->iov_len - offset);

    offset = 0;
    if (copy_to_user(base, kdata, copy)) {
      goto out;
    }
    kdata += copy;
    len -= copy;
    iov++;
  }
  err = 0;

out:
  return err;
}

/************************************************************************
 * Connection teardown functions (common to both server and client).
 ************************************************************************/

static int
xen_release (struct socket *sock) {
  struct sock            *sk = sock->sk;
  struct xen_sock        *x;
  struct descriptor_page *d;

  TRACE_ENTRY;
  if (!sk) {
    return 0;
  }

  sock->sk = NULL;
  x = xen_sk(sk);
  d = x->descriptor_addr;

  // if map didn't succeed, gracefully exit 
  if (x->descriptor_handle == -1) 
    goto out;

  if (x->is_server) {
    while (atomic_read(&d->sender_has_shutdown) == 0 ) {
    }

    server_unallocate_buffer_pages(x);
    server_unallocate_descriptor_page(x);
  }
  
  if (x->is_client) {
    if ((atomic_read(&d->sender_has_shutdown)) == 0) {
      client_unmap_buffer_pages(x);
      client_unmap_descriptor_page(x);
      notify_remote_via_evtchn(x->evtchn_local_port);
    }
    else {
      printk(KERN_CRIT "    xen_release: SENDER ALREADY SHUT DOWN!\n");
    }
  }

out:
  sock_put(sk);

  TRACE_EXIT;
  return 0;
}

static void
server_unallocate_buffer_pages (struct xen_sock *x) {
  if (x->buffer_grefs) {
    int buffer_num_pages = (1 << x->buffer_order);
    int i;

    for (i = 0; i < buffer_num_pages; i++) {
      if (x->buffer_grefs[i] == -ENOSPC) {
        break;
      }

      gnttab_end_foreign_access(x->buffer_grefs[i], 0);
      x->buffer_grefs[i] = -ENOSPC;
    }

    kfree(x->buffer_grefs);
    x->buffer_grefs = NULL;
  }

  if (x->buffer_addr) {
    struct descriptor_page *d = x->descriptor_addr;

    free_pages(x->buffer_addr, x->buffer_order);
    x->buffer_addr = 0;
    x->buffer_order = -1;
    if (d) {
      d->buffer_order = -1;
    }
  }
}

static void
server_unallocate_descriptor_page (struct xen_sock *x) {
  if (x->descriptor_gref != -ENOSPC) {
    gnttab_end_foreign_access(x->descriptor_gref, 0);
    x->descriptor_gref = -ENOSPC;
  }
  if (x->descriptor_addr) {
    free_page((unsigned long)(x->descriptor_addr));
    x->descriptor_addr = NULL;
  }
}

static void
client_unmap_buffer_pages (struct xen_sock *x) {

  if (x->buffer_handles) {
    struct descriptor_page *d = x->descriptor_addr;
    int                     buffer_order = d->buffer_order;
    int                     buffer_num_pages = (1 << buffer_order);
    int                     i;
    struct                  gnttab_unmap_grant_ref op;
    int                     rc = 0;

    for (i = 0; i < buffer_num_pages; i++) {
      if (x->buffer_handles[i] == -1) {
        break;
      }

      memset(&op, 0, sizeof(op));
      op.host_addr = x->buffer_addr + i * PAGE_SIZE;
      op.handle = x->buffer_handles[i];
      op.dev_bus_addr = 0;

      //lock_vm_area(x->buffer_area);
      rc = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1);
      //unlock_vm_area(x->buffer_area);
      if (rc == -ENOSYS) {
        printk("Failure to unmap grant reference \n");
      }
    }

    kfree(x->buffer_handles);
    x->buffer_handles = NULL;
  }
  if (x->buffer_area) {
    free_vm_area(x->buffer_area);
    x->buffer_area = NULL;
  }
}

static void
client_unmap_descriptor_page (struct xen_sock *x) {
  struct descriptor_page *d;
  int                     rc = 0;

  d = x->descriptor_addr;

  if (x->descriptor_handle != -1) {
    struct gnttab_unmap_grant_ref op;

    memset(&op, 0, sizeof(op));
    op.host_addr = (unsigned long)x->descriptor_addr;
    op.handle = x->descriptor_handle;
    op.dev_bus_addr = 0;

    //lock_vm_area(x->descriptor_area);
    atomic_set(&d->sender_has_shutdown, 1);
    rc = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &op, 1);
    //unlock_vm_area(x->descriptor_area);
    if (rc == -ENOSYS) {
      printk("Failure to unmap grant reference for descriptor page\n");
    }

    x->descriptor_handle = -1;
  }
  if (x->descriptor_area) {
    free_vm_area(x->descriptor_area);
    x->descriptor_area = NULL;
  }
}


/************************************************************************
 * Functions to interface this module with the rest of the Linux streams
 * code.
 ************************************************************************/

static int __init
xensocket_init (void) {
  int rc = -1;

  TRACE_ENTRY;

  rc = proto_register(&xen_proto, 1);
  if (rc != 0) {
    printk(KERN_CRIT "%s: Cannot create xen_sock SLAB cache!\n", __FUNCTION__);
    goto out;
  }

  sock_register(&xen_family_ops);

out:
  TRACE_EXIT;
  return rc;
}

static void __exit
xensocket_exit (void) {
  TRACE_ENTRY;

  sock_unregister(AF_XEN);
  proto_unregister(&xen_proto);

  TRACE_EXIT;
}

module_init(xensocket_init);
module_exit(xensocket_exit);

MODULE_LICENSE("GPL");
