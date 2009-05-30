/* -*- mode: C; c-file-style: "k&r"; c-basic-offset: 3; indent-tabs-mode: nil; -*- */
/*
 * Periscope - Argus Client Interface
 * Copyright (c) 2009 Harry Bock <harry@oshean.org>
 * 
 * Modified from 'ra', written by Carter Bullard.
 * Argus Software
 * Copyright (c) 2000-2009 QoSient, LLC
 * All rights reserved.
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
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "periscope.h"

struct PeriscopeCollector g_collector;

void
process_flow(struct PeriscopeCollector *collector,
             unsigned char type,
             struct ArgusRecordStruct *record,
             struct PeriscopeDSRs *dsrs)
{
   struct ArgusFlow *flow = dsrs->flow;

   if(!flow)
      printf("lol?\n");

   switch(type) {
   case ARGUS_TYPE_IPV4: {
      unsigned int ipaddr1, ipaddr2;
      char ip1[INET_ADDRSTRLEN];
      char ip2[INET_ADDRSTRLEN];
      struct ArgusIPFlow *ip = &flow->ip_flow;

      ipaddr1 = htonl(ip->ip_src);
      ipaddr2 = htonl(ip->ip_dst);
      
      inet_ntop(AF_INET, (struct in_addr *)&ipaddr1, ip1, sizeof(ip1));
      inet_ntop(AF_INET, (struct in_addr *)&ipaddr2, ip2, sizeof(ip2));

      switch(ip->ip_p) {
      case IPPROTO_TCP:
         printf("tcp: "); collector->metrics.tcp_count++;
         switch(net_subtype(dsrs->net)) {
         case ARGUS_TCP_PERF: {
            struct ArgusTCPObject *tcp = net_tcp(dsrs->net);
            printf("status: %08x ", tcp->status);
            if(tcp->status & ARGUS_RESET) {
               printf("RESET - ");
            }
            if(tcp->status & ARGUS_PKTS_RETRANS)
               printf("RETRANSMIT - ");
            if(tcp->status & ARGUS_NORMAL_CLOSE)
               printf("NORMAL CLOSE - ");
         }
            break;

         case ARGUS_TCP_STATUS:
            printf("status");
            break;

         case ARGUS_TCP_INIT:
            printf("init");
            break;

         default:
            printf("???");
            break;
         }
         printf("\n");

         break;
      case IPPROTO_UDP: collector->metrics.udp_count++; break;
      case IPPROTO_ICMP:
         if(dsrs->net) {
            struct ArgusICMPObject *icmp = net_icmp(dsrs->net);
            printf("ICMP (net subtype %02X): ", net_subtype(dsrs->net));
            printf("%15s %15s\n", ip1, ip2);
            printf("Type %02X Code %02X %04X seq\n", icmp->icmp_type, icmp->icmp_code, icmp->iseq);
         }
         collector->metrics.icmp_count++;
         break;
      default: collector->metrics.other_count++; break;
      }

      break;
   }

   default:
      printf("Unhandled flow type %02X.\n.", type);
   }
   
   if(dsrs->vlan) {
        
   }
   if(dsrs->metric) {
      struct ArgusMetricStruct *metric = dsrs->metric;
   }
   collector->metrics.flows++;
}

void
input_source_completed(struct PeriscopeCollector *collector,
                       struct ArgusInput *input)
{
   printf("Completed processing input source ");
   if(input->hostname)
      printf("%s:%d", input->hostname, input->portnum);
   else if(input->filename)
      printf("(file '%s')", input->filename);
   printf(".\n");

   printf("Processed %u flows (%u TCP, %u UDP, %u ICMP, %u other).\n",
          collector->metrics.flows, collector->metrics.tcp_count,
          collector->metrics.udp_count, collector->metrics.icmp_count,
          collector->metrics.other_count);
   
   collector->sources++;
   
   periscope_reset_metrics(collector);
}

int
main (int argc, char **argv)
{
   int i;
   periscope_collector_init(&g_collector);

   g_collector.callbacks.process_flow = process_flow;
   g_collector.callbacks.input_complete = input_source_completed;

   if(periscope_argus_client_init(&g_collector) == -1) {
        fprintf(stderr, "Initializing Argus client failed!\n");
        exit(1);
   }

   for(i = 0; i < (argc - 1); i++) {
      periscope_argus_add_file(&g_collector, argv[1+i]);
   }
   
   periscope_collector_start(&g_collector);
   periscope_collector_stop(&g_collector);
}
