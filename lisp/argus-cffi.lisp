;;;; Periscope - Network auditing tool
;;;; Copyright (C) 2009 Harry Bock <harry@oshean.org>

;;;; This file is part of Periscope.

;;;; periscope is free software; you can redistribute it and/or modify
;;;; it under the terms of the GNU General Public License as published by
;;;; the Free Software Foundation; either version 2 of the License, or
;;;; (at your option) any later version.

;;;; periscope is distributed in the hope that it will be useful,
;;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;;; GNU General Public License for more details.

;;;; You should have received a copy of the GNU General Public License
;;;; along with periscope; if not, write to the Free Software
;;;; Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
(in-package :periscope)

(defcstruct argus-dsr-header
  (type :uchar)
  (subtype :uchar)
  (dsr_un :uint16))

(defcstruct argus-ip-flow
  (ip-src :uint32)
  (ip-dst :uint32)
  (ip-proto :uint8)
  (tp-proto :uint8)
  (source-port :uint16)
  (dest-port :uint16)
  (pad :uint16))

(defcstruct argus-ipv6-flow
  (ip-src :uint32 :count 4)
  (ip-dst :uint32 :count 4)
  (flow-protocol :uint32)
  (source-port :uint16)
  (dest-port :uint16))

(defcstruct argus-icmp-flow
  (ip-src :uint32)
  (ip-dst :uint32)
  (ip-proto :uint8)
  (tp-proto :uint8)
  (type :uint8)
  (code :uint8)
  (id :uint16)
  (ip-id :uint16))

(defcunion argus-flow-union
  (ip argus-ip-flow)
  (ip6 argus-ipv6-flow)
  (icmp argus-icmp-flow))

(defcstruct argus-flow
  (hdr argus-dsr-header)
  (flow-un argus-flow-union))

(defcenum argus-flow-types
  (:ipv4 #x01)
  (:ipv6 #x02)
  (:ethernet #x03)
  (:arp  #x04)
  (:rarp #x05)
  (:mpls #x06)
  (:vlan #x07)
  (:ib   #x08)
  (:lcp  #x09)
  (:isis #x0A))

(defbitfield argus-tcp-state
  (:saw-syn       #x00000001)
  (:saw-syn-sent  #x00000002)
  (:established   #x00000004)
  (:fin           #x00000008)
  (:fin-ack       #x00000010)
  (:normal-close  #x00000020)
  (:close-waiting #x00000040)
  (:src-packets-retransmitted  #x00000100)
  (:dest-packets-retransmitted #x00000100)
  (:src-reset  #x000001000)
  (:dest-reset #x000002000))

(declaim (inline get-icmp get-ip))
(defun get-ip (flow)
  (foreign-slot-value (foreign-slot-value flow 'argus-flow 'flow-un) 'argus-flow-union 'ip))
(defun get-icmp (flow)
  (foreign-slot-value (foreign-slot-value flow 'argus-flow 'flow-un) 'argus-flow-union 'icmp))