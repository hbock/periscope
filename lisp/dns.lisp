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

(defvar *dns-thread*)
(defvar *dns-lock* (bt:make-lock "dns"))
(defvar *dns-cond* (bt:make-condition-variable))

(defvar *dns-requests* nil)
(defvar *dns-cache* (make-hash-table :size 10000))

(defun ip-to-vector (ip)
  "Convert an integer IP address to a 4-element vector as required by SB-BSD-SOCKETS."
  (declare (type (unsigned-byte 32) ip))
  (vector
   (ldb (byte 8 24) ip)
   (ldb (byte 8 16) ip)
   (ldb (byte 8  8) ip)
   (ldb (byte 8  0) ip)))

(defun vector-to-ip (vector)
  "Convert an IPv4 address in vector form to a 32-bit integer."
  (the (unsigned-byte 32)
    (logior
     (ash (aref vector 0) 24)
     (ash (aref vector 1) 16)
     (ash (aref vector 2)  8)
     (ash (aref vector 3)  0))))

(defun start-dns ()
  "Start the DNS resolver thread."
  (unless (and (boundp '*dns-thread*) (bt:thread-alive-p *dns-thread*))
    (setf *dns-available-p* t)
    (setf *dns-thread* (bt:make-thread #'dns-thread :name "DNS Reverse Lookups"))))

(defun stop-dns (&key (join t))
  "Stop and optionally join the DNS resolver thread."
  (setf *dns-available-p* nil)
  (bt:condition-notify *dns-cond*)
  (when join
    (bt:join-thread *dns-thread*)))

(defun clear-dns ()
  "Clear the current DNS cache."
  (clrhash *dns-cache*))

(defun dns-thread ()
  (loop :while *dns-available-p* :do
     (let ((host
	    (bt:with-lock-held (*dns-lock*)
	      (cond
		((null *dns-requests*) (bt:condition-wait *dns-cond* *dns-lock*))
		(t (setf *dns-requests* (remove-duplicates *dns-requests*))
		   (pop *dns-requests*))))))
       (when host
	 (let ((hostname
		;; Attempt to force a 1-second timeout on all DNS requests.
		;; Most lookups that take more than that end up being NXDOMAIN.
		(with-timeout (1)
		  (reverse-lookup host))))
	   (bt:with-lock-held (*dns-lock*)
	     (setf (gethash host *dns-cache*) hostname)))))))

(defun reverse-lookup (ip)
  #+sbcl
  (handler-case 
      (sb-bsd-sockets:host-ent-name
       (sb-bsd-sockets:get-host-by-address (ip-to-vector ip)))
    (sb-bsd-sockets:name-service-error (e)
      (declare (ignore e)) nil))
  #-sbcl (not-implemented 'reverse-lookup))

(defun lookup (hostname)
  #+sbcl
  (handler-case
      (vector-to-ip
       (sb-bsd-sockets:host-ent-address
	(sb-bsd-sockets:get-host-by-name hostname)))
    (sb-bsd-sockets:name-service-error (e)
      (declare (ignore e)) nil))
  #-sbcl (not-implemented 'reverse-lookup))

(defun hostname (ip)
  "Given an IP address, lookup the hostname of the corresponding machine, if available.
Returns the IP address as a string on lookup failure."
  (cond
    ((any-broadcast-address-p ip)
     (format nil "~a [Broadcast]" (ip-string ip)))
    ((multicast-address-p ip)
     (format nil "~a [Multicast]" (ip-string ip)))
    
    (*dns-available-p*
     (bt:with-lock-held (*dns-lock*)
       (multiple-value-bind (hostname existp)
	   (gethash ip *dns-cache*)
	 (if existp
	     (if hostname
		 (values hostname :found)
		 (values (ip-string ip) :nxdomain))
	     (progn
	       (push ip *dns-requests*)
	       (bt:condition-notify *dns-cond*)
	       (values (ip-string ip) :processing))))))
    (t (values (ip-string ip) :unavailable))))