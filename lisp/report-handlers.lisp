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

(defun make-filtered-reports (flow-list &optional time user)
  "Return a list of report structures in the form (time filter &rest reports)
corresponding to user's filters, as applied to the flows in flow-list. If no
filters are defined, a list with the form (time nil &rest reports) is returned."
  (if (and user (filters user))
      (loop :for flows :in (apply-filters flow-list (filter-predicates user))
	 :for filter :in (filters user) :collect
	 (list time
	       filter
	       (make-periodic-report flows)
	       (make-service-report flows)))
      (list
       (list time
	     nil
	     (make-periodic-report flow-list)
	     (make-service-report flow-list)))))

(defun in-report-directory (filespec &optional (directory *report-directory*))
  (ensure-directories-exist (merge-pathnames filespec directory)))

(defun hourly-log (time &optional (directory *report-directory*))
  "Return the hourly Argus log pathname corresponding to time, searching in directory."
  (multiple-value-bind (sec min hour date month year)
      (decode-universal-time time)
    (declare (ignore sec min))
    (merge-pathnames (format nil "hourly.~d~2,'0d~2,'0d-~2,'0d" year month date hour)
		     directory)))

(defun hourly-logs (&optional (pathspec *report-directory*))
  "Find all files in pathspec matching the following filename format: hourly.YYYYMMDD-HH, where
Y = year, M = month, D = date, and H = hour. Returns a list of all such hourly Argus logs as a
dotted list with the CAR being the universal time indicated in the filename and the CDR being
the pathname of the log itself."
  (let (reports)
    (dolist (file (fad:list-directory pathspec))
      (let ((time
	     (ppcre:register-groups-bind ((#'parse-integer year month day hour))
		 ("hourly.(\\d{4})(\\d{2})(\\d{2})-(\\d{2})" (namestring file))
	       (encode-universal-time 0 0 hour day month year))))
	(when time
	  (push (cons time file) reports))))
    (sort (nreverse reports) #'< :key #'car)))

(defun last-hourly-log (&optional (pathspec *report-directory*))
  "Return the most newly generated hourly Argus log."
  (first (reverse (hourly-logs pathspec))))

(defun print-hourly-list ()
  (with-html-output (*standard-output*)
    (:div
     :class "report-listing"
     (:h2 "Hourly Report Listing")
     (let ((logs (hourly-logs)))
       (when (null logs)
	 (htm (:br) "No hourly reports available!"))
       (loop
	  :with first = t
	  :with current-day = 0
	  :for log :in logs :do
	  (let ((log-time (car log)))
	    (multiple-value-bind (sec min hour)
		(decode-universal-time log-time)
	      (declare (ignore sec min))
	      (when (/= (this-day log-time) current-day)
		(setf current-day (this-day log-time))
	     
		(htm (if first
			 (setf first nil)
			 (htm (:br) (:br)))
		     (:b (str (long-date-string
			       (universal-to-timestamp current-day) :minutes nil)))
		     (:br))
	     
		(if (< hour 12)
		    (htm (:b "AM "))
		    (htm (:b "PM "))))

	      (when (= 12 hour)
		(htm (:br) (:b "PM ")))
	   
	      (htm (:a :href (format nil "/hourly?time=~d" log-time)
		       (fmt "~2,'0d:00" hour))))))))))

(define-report-handler (hourly "/hourly" "Hourly Traffic")
    ((time :parameter-type 'integer))
  (with-periscope-page ("Hourly Traffic Reports")
    (if time
	(handler-case
	    (let* ((flows (process-local-file (probe-file (hourly-log time))))
		   (report-lists (make-filtered-reports flows time (user))))
	      (htm
	       (:h2 "Hourly Report")
	       (:a :href "/hourly" "Back to all hourly reports")
	       (:div :class "stats"
		     (dolist (report-list report-lists)
		       (destructuring-bind (time filter &rest reports) report-list
			 (htm
			  (:h3 (str (long-date-string (universal-to-timestamp time))))
			  (when filter (print-html filter)))
			 
			 (dolist (report reports)
			   (print-html report)))
		       (htm (:hr))))))
	  ;; PROCESS-LOCAL-FILE can throw PERISCOPE-FILE-ERROR to indicate file-not-found
	  (file-error () (hunchentoot:redirect "/nothingtoseehere")))
	;; When 'time' GET parameter is not specified, print the list of all available
	;; reports.
	(print-hourly-list))))
