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

(defclass collector ()
  ((ptr :initform nil :accessor get-ptr)))

(defmethod initialize-instance :after ((object collector) &key)
  (let ((ptr (foreign-alloc 'periscope-collector)))
    (setf (get-ptr object) ptr)
    (when (minusp (%collector-init ptr))
      (foreign-free ptr)
      (error "Unable to initialize collector!"))
    (tg:finalize object (lambda ()
			  (%collector-free ptr)
			  (foreign-free ptr)))))

(defmethod run ((object collector))
  "Start the collector."
  (when (running-p object)
    (error "Collector is already running."))
  (when (minusp (%collector-run (get-ptr object)))
    (error "Failed to start collector.")))

(defmethod stop ((object collector))
  "Stop the collector, closing all open files and connections."
  (%collector-stop (get-ptr object)))

(defmethod add-remote ((collector collector) (host string))
  "Add a remote host to be processed when START is called."
  (when (null-pointer-p (%argus-remote-add (get-ptr collector) host))
    (error "Error adding host ~a to the collector." host)))

(defgeneric add-file (collector file)
  (:documentation "Add a local Argus file to be processed when START is called."))

(defmethod add-file ((collector collector) (file string))
  (when (minusp (%argus-local-add (get-ptr collector) file))
    (if (not (probe-file file))
	(error "File ~a does not exist!" file)
	(error "Failed to add file ~a to the collector." file)))
  file)

(defmethod add-file ((collector collector) (file pathname))
  (add-file collector (namestring file)))

(defmethod connect ((collector collector) (host string))
  "Connect directly to a remote Argus server at HOST."
  (when (minusp (%argus-remote-direct-connect (get-ptr collector) host))
    (error "Failed to connect to host ~a!" host)))

(defmethod running-p ((collector collector))
  (plusp (%collector-running-p (get-ptr collector))))
