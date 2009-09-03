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

(defclass report-collection ()
  ((log :initarg :log :reader report-log)
   (timestamp :initarg timestamp :reader report-timestamp)
   (filter :initarg :filter :reader report-filter :initform nil)
   (reports :initarg :reports :reader report-list :initform nil)
   (generated :reader report-generation-time
	      :initform (simple-date:universal-time-to-timestamp
			 (get-universal-time)))))

(defmethod initialize-instance :after ((object report-collection) &key)
  (unless (slot-boundp object 'timestamp)
    (with-slots (timestamp log) object
      (setf timestamp (argus-log-timestamp log))))

  (with-slots (timestamp reports) object
    (setf reports (mapcar (lambda (type) (make-instance type :time timestamp)) reports))))

(defmethod process-log ((log argus-log) &key (collector (init-basic-collector)) user argus-filter)
  (when argus-filter
    (setf (filter collector) argus-filter))
  (add-file collector (argus-log-pathname log))

  (setf (current-report collector)
	(make-instance 'report-collection
		       :log log
		       :filter (when user (first (filters user)))
		       :reports (list 'periodic-report 'service))
	;; TODO: REMOVE ME!
	*collector* collector)

  (with-database ("periscope")
    (execute "TRUNCATE TABLE host_stat")
    (run collector)
    (dolist (report (report-list (current-report collector)))
      (finalize-report report)))

  (current-report collector))

(defmethod process-flow ((collector collector) (flow flow))
  (with-slots (filter reports) (current-report collector)
    (when (or (null filter)
	      (filter-pass-p filter flow))
      (dolist (report reports)
	(add-flow report flow)))))

(defmethod print-html ((object report-collection) &key)
  (with-html-output (*standard-output*)
    (with-slots (filter reports) object
      (when filter (print-html filter))
      (dolist (report reports)
	(htm (:div :class "stats" (print-html report)))))))

(defmethod print-object ((object report-collection) stream)
  (print-unreadable-object (object stream :type t)
    (with-slots (reports timestamp) object
      (format stream "reports (~{~a~^, ~}) @[~a]" (mapcar #'type-of reports)
	      (timestamp-string timestamp)))))