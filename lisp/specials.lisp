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

;; Temporary vars (will go away eventually)
(defvar *flow-list* nil)

;; Version and compilation time
(defvar *periscope-version* "0.9.90 (pre-alpha)")
(defvar *compilation-time* (get-universal-time))

(defvar *web-port* 20570)
(defvar *web-server* nil)
(defvar *web-show-diag* nil)

(defvar *collector* nil)

(defvar *swank-port* 20571)
(defvar *enable-swank-p* nil)

(defvar *report-handler-list* nil)
(defvar *notable-ports* (list 22 53 80 443 51413))
(defvar *service-cache* (make-hash-table :test #'equal :size 500))

(defvar *internal-network* #x0a000000)
(defvar *internal-netmask* #x0affff00)

(defconstant +ip-proto-icmp+ 1)
(defconstant +ip-proto-igmp+ 2)
(defconstant +ip-proto-tcp+  6)
(defconstant +ip-proto-udp+  17)

(defconstant +vlan-none+ 0)
