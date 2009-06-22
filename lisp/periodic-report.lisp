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

(defclass stats ()
  ((flows :initarg :flows :accessor flows :initform 0)
   (bytes :initarg :bytes :accessor bytes :initform 0)
   (packets :initarg :packets :accessor packets :initform 0)))

(defclass periodic-report (report)
  ((total :accessor total)
   (internal :accessor internal)
   (external :accessor external)
   (incoming :accessor incoming)
   (outgoing :accessor outgoing)))

(defmethod initialize-instance :after ((object periodic-report)
				       &key (flow-list (error "Need flows!")))
  (with-slots (total internal external incoming outgoing) object
    (setf (total object)
	  (make-instance 'stats
			 :flows (length flow-list)
			 :packets
			 (reduce #'+ flow-list 
				 :key (lambda (flow)
					(with-slots (packets-source packets-dest) flow
					  (+ packets-source packets-dest))))
			 :bytes
			 (reduce #'+ flow-list 
				 :key (lambda (flow)
					(with-slots (bytes-source bytes-dest) flow
					  (+ bytes-source bytes-dest)))))
	  internal (make-instance 'stats)
	  external (make-instance 'stats)
	  incoming (make-instance 'stats)
	  outgoing (make-instance 'stats))
  
    (dolist (flow flow-list)
      (with-slots (packets-source packets-dest bytes-source bytes-dest) flow
	(let ((bytes (+ bytes-source bytes-dest))
	      (packets (+ packets-source packets-dest)))
	  (case (classify flow)
	    (:internal-only (add-stats internal :bytes bytes :packets packets))
	    (:external-only (add-stats external :bytes bytes :packets packets))
	    (:incoming  (add-stats incoming :bytes bytes :packets packets))
	    (:outgoing  (add-stats outgoing :bytes bytes :packets packets))))))))

(defmethod print-html ((object stats) &key (title "General Stats"))
  (with-html-output (*standard-output*)
    (:tr (:th (str title))
	 (:td (fmt "~:d" (packets object)))
	 (:td (str (byte-string (bytes object))))
	 (:td (fmt "~:d" (flows object))))))

(defmethod add-stats ((object stats) &key (flows 1) (bytes 0) (packets 0))
  (incf (flows object) flows)
  (incf (bytes object) bytes)
  (incf (packets object) packets))