/*
 * Copyright (c) 2004-2005 The Trustees of Indiana University and Indiana
 *                         University Research and Technology
 *                         Corporation.  All rights reserved.
 * Copyright (c) 2004-2005 The University of Tennessee and The University
 *                         of Tennessee Research Foundation.  All rights
 *                         reserved.
 * Copyright (c) 2004-2005 High Performance Computing Center Stuttgart,
 *                         University of Stuttgart.  All rights reserved.
 * Copyright (c) 2004-2005 The Regents of the University of California.
 *                         All rights reserved.
 * Copyright (c) 2006      Sandia National Laboratories. All rights
 *                         reserved.
 * Copyright (c) 2007      The Regents of the University of California.
 *                         All rights reserved.
 * Copyright (c) 2013-2016 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2015      Intel, Inc. All rights reserved
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "opal_config.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "opal/prefetch.h"
#include "opal/types.h"
#include "opal/util/show_help.h"

#include "btl_usnic.h"
#include "btl_usnic_endpoint.h"
#include "btl_usnic_module.h"
#include "btl_usnic_frag.h"
#include "btl_usnic_proc.h"
#include "btl_usnic_util.h"
#include "btl_usnic_ack.h"
#include "btl_usnic_send.h"

/*
 * Construct/destruct an endpoint structure.
 */
static void endpoint_construct(mca_btl_base_endpoint_t* endpoint)
{
    int i;

    endpoint->endpoint_module = NULL;
    endpoint->endpoint_proc = NULL;
    endpoint->endpoint_proc_index = -1;
    endpoint->endpoint_exiting = false;
    endpoint->endpoint_connectivity_checked = false;
    endpoint->endpoint_on_all_endpoints = false;

    for (i = 0; i < USNIC_NUM_CHANNELS; ++i) {
        endpoint->endpoint_remote_modex.ports[i] = 0;
        endpoint->endpoint_remote_addrs[i] = FI_ADDR_NOTAVAIL;
    }

    endpoint->endpoint_send_credits = 8;

    /* list of fragments queued to be sent */
    OBJ_CONSTRUCT(&endpoint->endpoint_frag_send_queue, opal_list_t);

    endpoint->endpoint_next_frag_id = 1;
    endpoint->endpoint_acktime = 0;

    /* endpoint starts not-ready-to-send */
    endpoint->endpoint_ready_to_send = 0;
    endpoint->endpoint_ack_needed = false;

    /* clear sent/received sequence number array */
    memset(endpoint->endpoint_sent_segs, 0,
           sizeof(endpoint->endpoint_sent_segs));
    memset(endpoint->endpoint_rcvd_segs, 0,
           sizeof(endpoint->endpoint_rcvd_segs));

    /* Defer setting up the OPAL hotel for this endpoint (setting up
       hotels are expensive -- set up a hotel upon first send/use). */
    endpoint->endpoint_fully_setup = false;

    /* Setup this endpoint's list links */
    OBJ_CONSTRUCT(&(endpoint->endpoint_ack_li), opal_list_item_t);
    OBJ_CONSTRUCT(&(endpoint->endpoint_endpoint_li), opal_list_item_t);
    endpoint->endpoint_ack_needed = false;

    /* fragment reassembly info */
    endpoint->endpoint_rx_frag_info =
        calloc(sizeof(struct opal_btl_usnic_rx_frag_info_t), MAX_ACTIVE_FRAGS);
    assert(NULL != endpoint->endpoint_rx_frag_info);
    if (OPAL_UNLIKELY(endpoint->endpoint_rx_frag_info == NULL)) {
        BTL_ERROR(("calloc returned NULL -- this should not happen!"));
        opal_btl_usnic_exit(endpoint->endpoint_module);
        /* Does not return */
    }
}

/*
 * Print a warning about how the remote peer was unreachable.
 *
 * This is a separate helper function simply because it's somewhat
 * bulky to put inline.
 */
static void warn_unreachable(opal_btl_usnic_endpoint_t *endpoint)
{
    /* Only show the warning if it is enabled */
    if (!mca_btl_usnic_component.show_route_failures) {
        return;
    }

    opal_btl_usnic_module_t *module = endpoint->endpoint_module;

    char remote[IPV4STRADDRLEN];
    opal_btl_usnic_snprintf_ipv4_addr(remote, sizeof(remote),
                                      endpoint->endpoint_remote_modex.ipv4_addr,
                                      endpoint->endpoint_remote_modex.netmask);

    opal_output_verbose(15, USNIC_OUT,
                        "btl:usnic: %s (which is %s) couldn't reach peer %s",
                        module->fabric_info->fabric_attr->name,
                        module->if_ipv4_addr_str,
                        remote);
    opal_show_help("help-mpi-btl-usnic.txt", "unreachable peer IP",
                   true,
                   opal_process_info.nodename,
                   module->if_ipv4_addr_str,
                   module->fabric_info->fabric_attr->name,
                   opal_get_proc_hostname(endpoint->endpoint_proc->proc_opal),
                   remote);
}

/* Part two of the endpoint setup: do the expensive (slow) things. We
 * defer this until we have to send to or receive from the given
 * peer (vs. doing this for every endpoint during add_procs).
 */
int opal_btl_usnic_endpoint_finish_setup(opal_btl_usnic_endpoint_t *endpoint)
{
    /* Make a new OPAL hotel for this endpoint.  The "hotel" is a
       construct used for triggering segment retransmission due to
       timeout. */
    OBJ_CONSTRUCT(&endpoint->endpoint_hotel, opal_hotel_t);
    opal_hotel_init(&endpoint->endpoint_hotel,
                    WINDOW_SIZE,
                    opal_sync_event_base,
                    mca_btl_usnic_component.retrans_timeout,
                    0,
                    opal_btl_usnic_ack_timeout);

    /* Add a destination to the fi_av vector for each channel */
    int ret;
    opal_btl_usnic_module_t *module = endpoint->endpoint_module;
    opal_btl_usnic_modex_t *modex = &endpoint->endpoint_remote_modex;

    char str[IPV4STRADDRLEN];
    opal_btl_usnic_snprintf_ipv4_addr(str, sizeof(str), modex->ipv4_addr,
                                      modex->netmask);
    opal_output_verbose(5, USNIC_OUT,
                        "btl:usnic: av_insert to %s:%d and :%d",
                        str,
                        modex->ports[USNIC_PRIORITY_CHANNEL],
                        modex->ports[USNIC_DATA_CHANNEL]);

    /* build remote address */
    struct sockaddr_in sin[USNIC_NUM_CHANNELS] = {{0}};
    for (int i = 0; i < USNIC_NUM_CHANNELS; ++i) {
        sin[i].sin_family = AF_INET;
        sin[i].sin_port = htons(modex->ports[i]);
        sin[i].sin_addr.s_addr = modex->ipv4_addr;
    }
    ret = fi_av_insert(module->av, &sin[0], USNIC_NUM_CHANNELS,
            &endpoint->endpoint_remote_addrs[0], 0, NULL);
    if (USNIC_NUM_CHANNELS != ret) {
        // Warn if the error was simply that the peer was unreachable
        for (int i = 0; i < USNIC_NUM_CHANNELS; ++i) {
            if (FI_ADDR_NOTAVAIL == endpoint->endpoint_remote_addrs[i]) {
                warn_unreachable(endpoint);
                return OPAL_ERR_UNREACH;
            }
        }

        // Some other kind of error
        opal_show_help("help-mpi-btl-usnic.txt", "libfabric API failed",
                       true,
                       opal_process_info.nodename,
                       module->fabric_info->fabric_attr->name,
                       "fi_av_insert()", __FILE__, __LINE__,
                       ret,
                       "Failed to initiate AV insert");
        return OPAL_ERROR;
    }


    endpoint->endpoint_fully_setup = true;
    return OPAL_SUCCESS;
}

static void endpoint_destruct(mca_btl_base_endpoint_t* endpoint)
{
    opal_btl_usnic_proc_t *proc;

    if (endpoint->endpoint_ack_needed) {
        opal_btl_usnic_remove_from_endpoints_needing_ack(endpoint);
    }
    OBJ_DESTRUCT(&(endpoint->endpoint_ack_li));

    /* Remove the endpoint from the all_endpoints list */
    opal_btl_usnic_module_t *module = endpoint->endpoint_module;
    opal_mutex_lock(&module->all_endpoints_lock);
    if (endpoint->endpoint_on_all_endpoints) {
        opal_list_remove_item(&module->all_endpoints,
                              &endpoint->endpoint_endpoint_li);
        endpoint->endpoint_on_all_endpoints = false;
    }
    opal_mutex_unlock(&module->all_endpoints_lock);
    OBJ_DESTRUCT(&(endpoint->endpoint_endpoint_li));

    if (endpoint->endpoint_fully_setup &&
        endpoint->endpoint_hotel.rooms != NULL) {
        OBJ_DESTRUCT(&(endpoint->endpoint_hotel));
    }

    OBJ_DESTRUCT(&endpoint->endpoint_frag_send_queue);

    /* release owning proc */
    proc = endpoint->endpoint_proc;
    if (NULL != proc) {
        proc->proc_endpoints[endpoint->endpoint_proc_index] = NULL;
        OBJ_RELEASE(proc);
    }

    free(endpoint->endpoint_rx_frag_info);
}

OBJ_CLASS_INSTANCE(opal_btl_usnic_endpoint_t,
                   opal_list_item_t,
                   endpoint_construct,
                   endpoint_destruct);

/*
 * Forcibly drain all pending output on an endpoint, without waiting for
 * actual completion.
 */
void
opal_btl_usnic_flush_endpoint(
    opal_btl_usnic_endpoint_t *endpoint)
{
    opal_btl_usnic_send_frag_t *frag;

    /* First, free all pending fragments */
    while (!opal_list_is_empty(&endpoint->endpoint_frag_send_queue)) {
        frag = (opal_btl_usnic_send_frag_t *)opal_list_remove_first(
                &endpoint->endpoint_frag_send_queue);

        /* _cond still needs to check ownership, but make sure the
         * fragment is marked as done.
         */
        frag->sf_ack_bytes_left = 0;
        frag->sf_seg_post_cnt = 0;
        opal_btl_usnic_send_frag_return_cond(endpoint->endpoint_module, frag);
    }

    /* Now, ACK everything that is pending */
    opal_btl_usnic_handle_ack(endpoint, endpoint->endpoint_next_seq_to_send-1);
}
