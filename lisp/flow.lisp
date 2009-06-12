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

(defclass flow ()
  ((ip-source :initarg :ip-source :reader flow-ip-source :initform (error "Must supply source IP!"))
   (ip-dest   :initarg :ip-dest   :reader flow-ip-dest :initform (error "Must supply destination IP!"))
   (protocol  :initarg :protocol  :reader flow-protocol :initform (error "Must supply IP protocol!"))
   (port-source :initarg :port-source :initform nil)
   (port-dest   :initarg :port-dest :initform nil)
   (packets-source :initarg :packets-source :initform 0)
   (packets-dest    :initarg :packets-dest :initform 0)
   (bytes-source   :initarg :bytes-source :initform 0)
   (bytes-dest     :initarg :bytes-dest :initform 0)))

(let ((row-switch t))
  (defmethod print-html ((object flow))
    (setf row-switch (not row-switch))
    (with-slots (ip-source ip-dest port-source port-dest protocol
			   packets-source packets-dest
			   bytes-source bytes-dest) object
      (with-html-output (*standard-output*)
	(:tr :class (if row-switch "rowa" "rowb")
	     (:td (str (ip-string ip-source)))
	     (:td (fmt "~d" port-source))
	     (:td (fmt "~d" packets-source))
	     (:td (str (ip-string ip-dest)))
	     (:td (fmt "~d" port-dest))
	     (:td (fmt "~d" packets-dest))
	     (:td (str (case protocol
			 (1 "ICMP")
			 (2 "IGMP")
			 (6 "TCP")
			 (17 "UDP")))))))))