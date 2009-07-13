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
(defvar *dns-available-p* t)
(defvar *dns-cache* (make-hash-table :size 10000))

(defun ip-to-vector (ip)
  "Convert an integer IP address to a 4-element vector as required by SB-BSD-SOCKETS."
  (declare (type (unsigned-byte 32) ip))
  (vector
   (ldb (byte 8 24) ip)
   (ldb (byte 8 16) ip)
   (ldb (byte 8  8) ip)
   (ldb (byte 8  0) ip)))

(defun start-dns ()
  (setf *dns-available-p* t)
  (setf *dns-thread* (bt:make-thread #'dns-thread :name "DNS Reverse Lookups")))

(defun stop-dns (&key (join t))
  (setf *dns-available-p* nil)
  (when join
    (bt:join-thread *dns-thread*)))

(defun dns-thread ()
  (loop :while *dns-available-p* :do
     (let ((host
	    (bt:with-lock-held (*dns-lock*)
	      (loop :while (null *dns-requests*) :do
		 (bt:condition-wait *dns-cond* *dns-lock*))
	      (setf *dns-requests* (remove-duplicates *dns-requests*))
	      (pop *dns-requests*))))
       (let ((hostname (reverse-lookup host)))
	 (bt:with-lock-held (*dns-lock*)
	   (setf (gethash host *dns-cache*) hostname))))))

(defun reverse-lookup (ip)
  (if (broadcast-address-p ip)
      "Broadcast"
      #+sbcl
      (handler-case 
	  (sb-bsd-sockets:host-ent-name
	   (sb-bsd-sockets:get-host-by-address (ip-to-vector ip)))
	(sb-bsd-sockets:name-service-error (e)
	  (declare (ignore e)) nil))
      #-sbcl nil))

(defun hostname (ip)
  "Given an IP address, lookup the hostname of the corresponding machine, if available.
Returns the IP address as a string on lookup failure."
  (cond
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