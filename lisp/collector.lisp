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
  ((ptr :initform nil :accessor get-ptr)
   (remote :initform nil :accessor remote-sources)))

(defclass source ()
  ((ptr :initarg :ptr :initform nil :accessor get-ptr)
   (path :initarg :path :initform nil :accessor source-path)
   (major-version :initarg :major-version :reader major-version)
   (minor-version :initarg :minor-version :reader minor-version)
   (hostname :initarg :hostname :reader hostname)
   (port :initarg :port :reader port)))

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
    (error "Failed to start collector."))
  (setf (remote-sources object) nil)
  object)

(defmethod stop ((object collector))
  "Stop the collector, closing all open files and connections."
  (%collector-stop (get-ptr object))
  object)

(defmethod add-remote ((collector collector) (host string) &optional (port 561))
  "Add a remote host to be processed when START is called."
  (let* ((hoststr (format nil "~a:~d" host port))
	 (ptr (%argus-remote-add (get-ptr collector) hoststr)))
    (when (null-pointer-p ptr)
      (error "Error adding host ~a to the collector." hoststr))
    (let ((source (make-instance 'source :ptr ptr :path host)))
      (push source (remote-sources collector)))))

(defgeneric add-file (collector file)
  (:documentation "Add a local Argus file to be processed when START is called."))

(defmethod add-file ((collector collector) (file string))
  (when (minusp (%argus-local-add (get-ptr collector) file))
    (if (not (probe-file file))
	(periscope-file-error "File ~a does not exist!" file)
	(periscope-file-error "Failed to add file ~a to the collector." file)))
  file)

(defmethod add-file ((collector collector) (file pathname))
  (add-file collector (namestring file)))

(defmethod connect ((collector collector) (host string))
  "Connect directly to a remote Argus server at HOST."
  (when (not (running-p collector))
    (error "Can't direct connect to hosts when collector is not running!"))
  (let ((ptr (%argus-remote-direct-connect (get-ptr collector) host)))
    (when (null-pointer-p ptr)
      (error "Failed to connect to host ~a!" host))
    (let ((source (make-instance 'source :ptr ptr :path host)))
      (push source (remote-sources collector)))))

(defmethod running-p ((collector collector))
  (plusp (%collector-running-p (get-ptr collector))))

(defmethod connected-p ((object source))
  (plusp (%argus-connected-p (get-ptr object))))

(defmethod filter ((object collector))
  (%argus-get-filter (get-ptr object)))

(defmethod (setf filter) ((filter string) (object collector))
  (when (minusp
	 (%argus-set-filter (get-ptr object) filter))
    (error "Syntax error in filter: '~a'" filter)))

(defun process-local-file (file &optional filter)
  (setf *flow-list* nil)
  (let ((collector (init-basic-collector)))
    (when filter
      (setf (filter collector) filter))
    (add-file collector file)
    (run collector))
  (setf *flow-list* (nreverse *flow-list*)))

(defmethod remote-port ((object source))
  (%argus-remote-port (get-ptr object)))

(defmethod remote-ip ((object source))
  (%argus-remote-ip (get-ptr object)))

(defun get-argus-sources (queue)
  (let (sources)
    (dolist (input (argus-queue-list queue))
      (with-foreign-object (info 'periscope-input-info)
	(unless (zerop (%argus-remote-info input info))
	  (error "Error getting info for ArgusInput ~a" input))
	(with-foreign-slots ((major-version minor-version hostname port) info periscope-input-info)
	  (push (make-instance 'source :major-version major-version
			       :minor-version minor-version
			       :hostname hostname
			       :port port
			       :ptr input
			       :path "NONE")
		sources))))
    sources))

(defmethod remove-source ((src source) (collector collector))
  (if (null-pointer-p (get-ptr src))
      (error "Cannot remove a NULL source!")
      (unless (zerop
	       (%argus-remote-remove (get-ptr collector) (get-ptr src)))
	(error "Failed to remove source at ~a!" (get-ptr src)))))

(defmethod available-sources ((object collector))
  (get-argus-sources (%argus-remote-pending-queue (get-ptr object))))

(defmethod active-sources ((object collector))
  (get-argus-sources (%argus-remote-active-queue (get-ptr object))))
