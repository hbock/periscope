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

(defun ip-to-vector (ip)
  "Convert an integer IP address to a 4-element vector as required by SB-BSD-SOCKETS."
  (declare (type (unsigned-byte 32) ip))
  (vector
   (ldb (byte 8 24) ip)
   (ldb (byte 8 16) ip)
   (ldb (byte 8  8) ip)
   (ldb (byte 8  0) ip)))

(defun hostname (ip)
  "Given an IP address, lookup the hostname of the corresponding machine, if available.
Returns an empty string on lookup failure."
  (if (broadcast-address-p ip)
      "Broadcast"
      #+sbcl
      (handler-case 
	  (sb-bsd-sockets:host-ent-name
	   (sb-bsd-sockets:get-host-by-address (ip-to-vector ip)))
	(sb-bsd-sockets:name-service-error (e)
	  (declare (ignore e))
	  ""))
      #-sbcl nil))