/* -*- mode: C; c-basic-offset: 3; indent-tabs-mode: nil; -*- */
/*
 * Periscope - Argus Client Interface
 * Copyright (c) 2009 Harry Bock <harry@oshean.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#ifndef __PERISCOPE_ARGUS_H
#define __PERISCOPE_ARGUS_H

#if defined(ARGUS_THREADS) 
#include <pthread.h>
#endif

#include <compat.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <argus_def.h>
#include <argus_out.h>

#include <argus_util.h>
#include <argus_client.h>

struct PeriscopeDSRs {
  struct ArgusFlow *flow;
  struct ArgusVlanStruct *vlan;
  struct ArgusMetricStruct *metric;
  struct ArgusTimeObject *time;
  struct ArgusNetworkStruct *net;
};

struct PeriscopeCollector;

typedef void (*PeriscopeProcessFlow)(struct PeriscopeCollector *collector,
				     unsigned char flow_type,
				     struct ArgusRecordStruct *record,
				     struct PeriscopeDSRs *dsrs);

typedef void (*PeriscopeInputComplete)(struct PeriscopeCollector *collector,
				       struct ArgusInput *input);

typedef void (*PeriscopeIdle)(struct PeriscopeCollector *collector);

struct PeriscopeCallbacks {
   PeriscopeIdle idle;
   PeriscopeProcessFlow process_flow;
   PeriscopeInputComplete input_complete;
};

struct PeriscopeMetrics {
   uint32_t flows;
   uint32_t tcp_count;
   uint32_t udp_count;
   uint32_t icmp_count;
   uint32_t other_count;
};

struct PeriscopeCollector {
   struct ArgusParserStruct *parser;
   
   struct PeriscopeCallbacks callbacks;
   struct PeriscopeMetrics metrics;

   uint32_t sources;
   uint8_t running;
};

#define periscope_callback(collector, callback, ...)			\
   do {									\
      if((collector)->callbacks.callback) {				\
	 (*(collector)->callbacks.callback)((collector), ##__VA_ARGS__ ); \
      }									\
   } while(0)								

/* Periscope core API. */
void periscope_reset_metrics(struct PeriscopeCollector *collector);

int periscope_collector_init(struct PeriscopeCollector *collector);
int periscope_collector_start(struct PeriscopeCollector *collector);
void periscope_collector_stop(struct PeriscopeCollector *collector);
void periscope_collector_free(struct PeriscopeCollector *collector);
int periscope_collector_is_running(struct PeriscopeCollector *collector);

/* Argus interface utility functions */
int periscope_argus_record_dsrs(struct ArgusRecordStruct *record,
				struct PeriscopeDSRs *dsrs);

int periscope_argus_client_init(struct PeriscopeCollector *collector);
int periscope_argus_client_stop(struct PeriscopeCollector *collector);
int periscope_argus_client_free(struct PeriscopeCollector *collector);

int periscope_argus_local_add(struct PeriscopeCollector *collector, char *pathname);
int periscope_argus_local_process(struct PeriscopeCollector *collector);

struct ArgusInput *
periscope_argus_remote_add(struct PeriscopeCollector *collector, char *hoststr);
int periscope_argus_remote_connect(struct PeriscopeCollector *collector, struct ArgusInput *remote);
int periscope_argus_remote_direct_connect(struct PeriscopeCollector *collector, char *hoststr);
int periscope_argus_remote_process(struct PeriscopeCollector *collector);

int periscope_argus_close_input(struct PeriscopeCollector *collector, struct ArgusInput *input);

/* Helper macros to access some Argus client data. */
#define record_type(rs)    ((rs)->hdr.type & 0xF0)

#define flow_type(flow)    ((flow)->hdr.argus_dsrvl8.qual)
#define flow_subtype(flow) ((flow)->hdr.subtype & 0x3F)
#define flow_ether(flow) ((flow)->mac_flow.mac_union.ether)

#define net_subtype(net) ((net)->hdr.subtype)
#define net_tcp(net)        (&(net)->net_union.tcp)
#define net_tcp_init(net)   (&(net)->net_union.tcpinit)
#define net_tcp_status(net) (&(net)->net_union.tcpstatus)
#define net_icmp(net)  (&(net)->net_union.icmp)
#define net_icmp6(net) (&(net)->net_union.icmp6)

inline struct ArgusFlow *
record_flow(struct ArgusRecordStruct *record);

inline struct ArgusVlanStruct *
record_vlan(struct ArgusRecordStruct *record);

inline struct ArgusMetricStruct *
record_metric(struct ArgusRecordStruct *record);

#endif
