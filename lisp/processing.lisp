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
   (filter :initarg :filter :reader filter :initform nil)
   (reports :initarg :reports :reader report-list :initform nil)
   (generated :reader report-generation-time
	      :initform (simple-date:universal-time-to-timestamp
			 (get-universal-time)))))

(defmethod initialize-instance :after ((object report-collection) &key)
  (unless (slot-boundp object 'timestamp)
    (with-slots (timestamp log) object
      (setf timestamp (argus-log-timestamp log))))

  (with-slots (timestamp reports filter) object
    (setf reports
	  (mapcar (lambda (type)
		    (make-instance type :time timestamp :filter filter)) reports))))

(defmethod commit ((collection report-collection) &key)
  (mapcar #'commit (report-list collection)))

(defmethod process-log ((log argus-log) &key (collector (init-basic-collector)) truncate)
  (add-file collector (argus-log-pathname log))
  (setf (reports collector)
  	(mapcar
	 (lambda (filter)
	   (make-instance 'report-collection
			  :log log
			  :filter filter
			  :reports (list 'general-stats 'service-report)))
	 (all-filters :compile t))
  	;; TODO: REMOVE ME!
  	*collector* collector)
  
  (with-database ("periscope")
    (when truncate
      (execute "TRUNCATE TABLE host_stat")
      (execute "TRUNCATE TABLE traffic_stats"))
    
    (run collector)
    (dolist (report (reports collector))
      (commit report)))

  (reports collector))

(defun process-log-group (log-list)
  (let (threads)
    (dolist (log log-list)
      (push (bt:make-thread (lambda () (process-log log))
			    :name (format nil "LOG PROCESSING ~a" log)) threads))

    (dolist (thread threads)
      (bt:join-thread thread))))

(defmethod print-html ((object report-collection) &key id hidden)
  (with-html-output (*standard-output*)
    (:div
     :id (format nil "r~d" id) :class "report" :style (when hidden "display:none")
     (with-slots (filter reports) object
       (when filter (print-html filter))
       (dolist (report reports)
	 (htm (:div :class "stats" (print-html report))))

       (htm
	(:p (:small
	     (fmt "Report generated at ~a."
		  (date-string (report-generation-time object) :minutes t)))))))))

(defmethod print-object ((object report-collection) stream)
  (print-unreadable-object (object stream :type t)
    (with-slots (reports timestamp filter) object
      ;; FORMAT RULEZ PRINTF DROOLZ
      (format stream "(~{~a~^, ~}) @[~a]~:[~; ~:*~S~]"
	      (mapcar #'type-of reports)
	      (timestamp-string timestamp)
	      (and filter (filter-title filter))))))