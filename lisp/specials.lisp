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
(defvar *compilation-time* (now))
(defparameter *periscope-version* "0.10.0 alpha3")

;;; And
;;;    here
;;;        we
;;;          GO!
(defvar *build-string*
  (format nil "0.9.96-~a"
	  (format-timestring nil *compilation-time*
			     :format '((:year 4) (:month 2) (:day 2)))))

;; Configuration
(defparameter *configuration-file-pathnames*
  (list #P"/etc/"
	(merge-pathnames ".periscope/" (user-homedir-pathname))))

(defvar *web-port* 20570)
(defvar *web-server* nil)
(defvar *web-show-diag* nil)
(defvar *web-login-required-p* nil)
(defvar *web-user-db* (make-hash-table :test #'equal))
(defvar *redirect-page* nil)

(defvar *rastream-binary* "rastream")

(defvar *collector* nil)
(defvar *collector-error-p* nil)
(defvar *collector-script* (truename #P"rastream-post.sh"))
(defvar *collector-process* nil)
(defvar *collector-default-filter* "tcp or icmp or udp")
(defvar *collector-argus-server* nil)
(defvar *collector-argus-port* 561)
(defvar *collector-shutdown-lock* (bt:make-lock))
(defvar *collector-shutdown-p* nil)

(defvar *current-report* nil)

(defvar *dns-available-p* t)

(defvar *swank-port* 20571)
(defvar *enable-swank-p* nil)

(defvar *report-handler-list* nil)
(defvar *report-directory* #P"reports/")

(defvar *notable-ports* (list 22 53 80 443 51413))

(defvar *service-cache* (make-hash-table :size 500))
(defvar *service-reverse-cache* (make-hash-table :test #'equal :size 500))

(defvar *vlan-names* (make-hash-table))

(defparameter *notable-ports* (list 22 53 80 443 51413))
(defparameter *internal-networks* (list (cons #x0a000000 #xffffff00)))

(defconstant +min-session-time+ 300
  "Minimum time (in seconds) a user can set HUNCHENTOOT:*MAX-SESSION-TIME*")

(defconstant +lowest-multicast-address+ #xe0000000)
(defconstant +highest-multicast-address+ #xefffffff)
(defconstant +highest-port-number+ #xffff)
(defconstant +broadcast-ip+ #xffffffff)
(defconstant +ip-proto-icmp+ 1)
(defconstant +ip-proto-igmp+ 2)
(defconstant +ip-proto-tcp+  6)
(defconstant +ip-proto-udp+  17)

(defconstant +vlan-none+ 0)
(defconstant +vlan-vid-mask+ #x0FFF)

(deftype vlan-id ()     '(unsigned-byte 12))
(deftype port-number () '(unsigned-byte 16))
