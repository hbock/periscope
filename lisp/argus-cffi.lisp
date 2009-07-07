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

(defcstruct argus-uni-stats
  #+cffi-features:no-long-long (error "No long long support! Required for statistics.")
  (packets  :long-long)
  (bytes    :long-long)
  (appbytes :long-long))

(defcstruct argus-metrics
  ;; I have to specify this manually for this to work on 64-bit SBCL.
  ;; Might have something to do with :long-long and padding?
  (source-stats argus-uni-stats :offset 4)
  (dest-stats argus-uni-stats   :offset 28))

(defcstruct argus-vlan
  (hdr argus-dsr-header)
  (sid :uint16)
  (did :uint16))

(defcstruct argus-time
  (start-sec  :int32)
  (start-usec :int32)
  (end-sec  :int32)
  (end-usec :int32))

(defcstruct argus-time-object
  (hdr argus-dsr-header)
  (src argus-time)
  (dst argus-time))

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
  (:dest-packets-retransmitted #x00000200)
  (:src-reset  #x000001000)
  (:dest-reset #x000002000))

(declaim (inline get-icmp get-ip get-flow get-metrics get-vlan))
(defun get-ip (flow)
  (foreign-slot-value (foreign-slot-value flow 'argus-flow 'flow-un) 'argus-flow-union 'ip))
(defun get-icmp (flow)
  (foreign-slot-value (foreign-slot-value flow 'argus-flow 'flow-un) 'argus-flow-union 'icmp))
(defun get-flow (dsrs)
  (foreign-slot-value dsrs 'periscope-dsrs 'flow))
(defun get-metrics (dsrs)
  (foreign-slot-value dsrs 'periscope-dsrs 'metric))
(defun get-vlan (dsrs)
  (foreign-slot-value dsrs 'periscope-dsrs 'vlan))

(defun argus-timestamp (sec usec)
  (unix-to-timestamp sec :nsec (* 1000 usec)))

(defun source-time (dsrs)
  (let ((time
	 (foreign-slot-value
	  (foreign-slot-value dsrs 'periscope-dsrs 'time) 'argus-time-object 'src)))
    (with-foreign-slots ((start-sec start-usec end-sec end-usec) time argus-time)
      (values (argus-timestamp start-sec start-usec)
	      (argus-timestamp end-sec end-usec)))))

(defun dest-time (dsrs)
  (let ((time
	 (foreign-slot-value
	  (foreign-slot-value dsrs 'periscope-dsrs 'time) 'argus-time-object 'dst)))
    (with-foreign-slots ((start-sec start-usec end-sec end-usec) time argus-time)
      (values (argus-timestamp start-sec start-usec)
	      (argus-timestamp end-sec end-usec)))))

(defun source-metrics (dsrs)
  (let ((stats
	 (foreign-slot-value
	  (foreign-slot-value dsrs 'periscope-dsrs 'metric)
	  'argus-metrics 'source-stats)))
    (with-foreign-slots ((packets bytes appbytes) stats argus-uni-stats)
      (values packets bytes appbytes))))

(defun dest-metrics (dsrs)
  (let ((stats
	 (foreign-slot-value
	  (foreign-slot-value dsrs 'periscope-dsrs 'metric)
	  'argus-metrics 'dest-stats)))
    (with-foreign-slots ((packets bytes appbytes) stats argus-uni-stats)
      (values packets bytes appbytes))))