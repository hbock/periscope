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

(define-foreign-library libperiscope
  (:unix "libperiscope.so"))

(use-foreign-library libperiscope)

(defcstruct periscope-callbacks
  (idle :pointer)
  (process_flow :pointer)
  (input_complete :pointer))

(defcstruct periscope-metrics
  (flows :uint32)
  (tcp-count :uint32)
  (udp-count :uint32)
  (icmp-count :uint32)
  (other-count :uint32))

(defcstruct periscope-collector
  (parser :pointer)
  (callbacks periscope-callbacks)
  (metrics periscope-metrics)
  (sources :uint32)
  (running :uint8))

;;; Argus DSR pointers
(defcstruct periscope-dsrs
  (flow :pointer)
  (vlan :pointer)
  (metric :pointer)
  (time :pointer)
  (net :pointer))

(defcstruct periscope-input-info
  (qhdr :pointer)
  (major-version :int)
  (minor-version :int)
  (hostname :string)
  (port :ushort))

(defcenum ip-protocols
  (:ip 0)
  (:icmp 1)
  (:igmp 2)
  (:ipip 4)
  (:tcp 6)
  (:udp 17)
  (:dccp 33)
  (:mtp 92))

(defcfun ("periscope_collector_init" %collector-init) :int
  (collector periscope-collector))

(defcfun ("periscope_collector_run" %collector-run) :int
  (collector periscope-collector))

(defcfun ("periscope_collector_is_running" %collector-running-p) :int
  (collector periscope-collector))

(defcfun ("periscope_collector_stop" %collector-stop) :void
  (collector periscope-collector))

(defcfun ("periscope_collector_free" %collector-free) :void
  (collector periscope-collector))

(defcfun ("periscope_argus_local_add" %argus-local-add) :int
  (collector periscope-collector)
  (pathname :string))

(defcfun ("periscope_argus_remote_add" %argus-remote-add) :pointer
  (collector periscope-collector)
  (hoststr :string))

(defcfun ("periscope_argus_remote_direct_connect" %argus-remote-direct-connect) :pointer
  (collector periscope-collector)
  (hoststr :string))

(defcfun ("periscope_argus_remote_remove" %argus-remote-remove) :int
  (collector periscope-collector)
  (input :pointer))

(defcfun ("periscope_argus_remote_info" %argus-remote-info) :int
  (collector periscope-collector)
  (input :pointer))

(defcfun ("periscope_argus_remote_is_connected" %argus-connected-p) :int
  (input :pointer))

(defcfun ("periscope_argus_remote_ip" %argus-remote-ip) :uint32
  (input :pointer))

(defcfun ("periscope_argus_remote_port" %argus-remote-port) :uint16
  (input :pointer))

(defcfun ("periscope_argus_remote_pending_queue" %argus-remote-pending-queue) :pointer
  (collector periscope-collector))

(defcfun ("periscope_argus_remote_active_queue" %argus-remote-active-queue) :pointer
  (collector periscope-collector))

(defcfun ("periscope_argus_set_filter" %argus-set-filter) :int
  (collector periscope-collector)
  (filter :string))

(defcfun ("periscope_argus_get_filter" %argus-get-filter) :string
  (collector periscope-collector))

(defcfun ("periscope_argus_debug_dsrs" %argus-debug-dsrs) :void
  (dsrs periscope-dsrs))

(defmacro with-collector-callbacks (callbacks collector &body body)
  `(with-foreign-slots ((,@callbacks)
			(foreign-slot-value (get-ptr ,collector) 'periscope-collector 'callbacks)
			periscope-callbacks)
     ,@body))
