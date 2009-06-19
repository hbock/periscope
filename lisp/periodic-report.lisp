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

(defclass periodic-report (report)
  ((total-flows :reader total-flows :initform 0)
   (total-bytes :reader total-bytes :initform 0)
   (total-packets :reader total-packets :initform 0)
   (internal-bytes :accessor internal-bytes :initform 0)
   (internal-packets :accessor internal-packets :initform 0)
   (external-bytes :accessor external-bytes :initform 0)
   (external-packets :accessor external-packets :initform 0)
   (incoming-bytes :accessor incoming-bytes :initform 0)
   (incoming-packets :accessor incoming-packets :initform 0)
   (outgoing-bytes :accessor outgoing-bytes :initform 0)
   (outgoing-packets :accessor outgoing-packets :initform 0)))

(defmethod initialize-instance :after ((object periodic-report)
				       &key (flow-list (error "Need flows!")))
  (with-slots (total-flows total-packets total-bytes) object
    (setf total-packets
	  (reduce #'+ flow-list 
		  :key (lambda (flow)
			 (with-slots (packets-source packets-dest) flow
			   (+ packets-source packets-dest))))
	  total-bytes
	  (reduce #'+ flow-list 
		  :key (lambda (flow)
			 (with-slots (bytes-source bytes-dest) flow
			   (+ bytes-source bytes-dest))))
	  total-flows (length flow-list))
    (dolist (flow flow-list)
      (with-slots (packets-source packets-dest bytes-source bytes-dest) flow
	(case (classify flow)
	  (:internal-only
	   (incf (internal-bytes object) (+ bytes-source bytes-dest))
	   (incf (internal-packets object) (+ packets-source packets-dest)))
	  (:external-only
	   (incf (external-bytes object) (+ bytes-source bytes-dest))
	   (incf (external-packets object) (+ packets-source packets-dest)))
	  (:incoming
	   (incf (incoming-bytes object) (+ bytes-source bytes-dest))
	   (incf (incoming-packets object) (+ packets-source packets-dest)))
	  (:outgoing
	   (incf (outgoing-bytes object) (+ bytes-source bytes-dest))
	   (incf (outgoing-packets object) (+ packets-source packets-dest))))))))