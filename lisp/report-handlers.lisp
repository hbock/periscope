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

(defmethod load-reports ((type symbol) (time simple-date:timestamp) &optional (user (user)))
  (declare (ignore type))
  (mapcar (lambda (filter)
	    (make-instance 'report-collection
			   :filter filter
			   :reports (list 'general-stats 'service-report)
			   :timestamp time))
	  (if user (user-filters user) (all-filters :active-only nil))))

(defun report-time-list (type &optional (user (user)))
  (declare (ignore type))
  (if user
      (query (:select (:distinct 'timestamp) :from 'traffic-stats :where
		      (:in 'filter-id (:set (filters user)))) :column)
      (query (:select (:distinct 'timestamp) :from 'traffic-stats) :column)))

(defun in-report-directory (filespec &optional (directory *report-directory*))
  (merge-pathnames filespec (truename (ensure-directories-exist directory))))

(defun hourly-log (time &optional (directory *report-directory*))
  "Return the hourly Argus log pathname corresponding to time, searching in directory."
  (multiple-value-bind (sec min hour date month year)
      (decode-universal-time time)
    (declare (ignore sec min))
    (let ((log
	   (probe-file
	    (merge-pathnames (format nil "hourly.~d~2,'0d~2,'0d-~2,'0d" year month date hour)
			     directory))))
      (if log
	  log
	  (periscope-file-error "Log file for time ~d does not exist in ~a!" time directory)))))

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

(defun daily-split-hourly-logs ()
  (let ((logs (hourly-logs)) day-logs log-list)
    (when logs
      (loop
	 :with day = (this-day (car (first logs)))
	 :for log :in logs
	 :if (= (this-day (car log)) day)
	 :do (push log day-logs)
	 :else :do
	 (push (nreverse day-logs) log-list)
	 (setf day-logs nil)
	 (setf day (this-day (car log)))
	 (push log day-logs))
      (when day-logs
	(push (nreverse day-logs) log-list))
      log-list)))

(defun print-report-list (type)
  (with-html-output (*standard-output*)
    (:div
     :class "report-listing"
     (:h2 "Report Listing")
     (let ((reports (report-time-list type)))
       (dolist (report reports)
	 (htm (:a :href (format nil "/~a?time=~d" (string-downcase type)
				(simple-date:timestamp-to-universal-time report))
		  (str (date-string report :minutes t))) (:br)))))))

(defun print-hourly-list ()
  "Print out the hourly log list HTML, with newest logs first."
  (with-html-output (*standard-output*)
    (:div
     :class "report-listing"
     (:h2 "Hourly Report Listing")
     (let ((daily-logs (daily-split-hourly-logs)))
       (when (null daily-logs)
	 (htm (:br) "No hourly reports available!")
	 (return-from print-hourly-list nil))

       (dolist (logs daily-logs)
	 (let ((log-day (this-day (car (first logs)))))
	   (htm (:br)
		(:b (str (long-date-string (universal-to-timestamp log-day) :minutes nil)))
		(:br)))
	 (loop
	    :for first = t :then nil
	    :for log :in logs :do
	    (let ((log-time (car log)))
	      (multiple-value-bind (sec min hour)
		  (decode-universal-time log-time)
		(declare (ignore sec min))
		(if first
		    (if (< hour 12)
			(htm (:b "AM "))
			(htm (:b "PM ")))
		    (when (= 12 hour)
		      (htm (:br) (:b "PM "))))
	      
		(htm (:a :href (format nil "/hourly?time=~d" log-time)
			 (fmt "~2,'0d:00" hour))))))
	 (htm (:br)))))))

(define-report-handler (hourly "/hourly" "Hourly Traffic")
    ((time :parameter-type 'integer))
  (with-periscope-page ("Hourly Traffic Reports" :database t)
    (if time
	(handler-case
	    (let (previous-time next-time)
	      (htm
	       (:h2 "Hourly Report")
	       (if previous-time
		   (htm (:a :href (format nil "/hourly?time=~d" previous-time) "Previous Report"))
		   (htm "Previous Report"))
	       " | "
	       (:a :href "/hourly" "Back to all hourly reports")
	       " | "
	       (if next-time
		   (htm (:a :href (format nil "/hourly?time=~d" next-time) "Next Report"))
		   (htm "Next Report"))
	       (htm
		(:div
		 :class "filter-list"
		 (:ul
		  (:li (:b "Filters"))
		  (loop
		     :for id = 0 :then (1+ id)
		     :for report in (reports *collector*) :do
		     (htm (:li (:a :href (format nil "javascript:displaySingleReport(~d);" id)
				   (str (filter-title (filter report))))))))
		 (:div :style "clear:both;")))
	       (loop
		  :for id = 0 :then (1+ id)
		  :for hidden = nil :then t
		  :for report in (reports *collector*)
		  :do (print-html report :id id :hidden hidden))))
	  
	  ;; PROCESS-LOCAL-FILE and HOURLY-LOG can throw PERISCOPE-FILE-ERROR
	  ;; to indicate file-not-found
	  (file-error () (hunchentoot:redirect "/nothingtoseehere")))
	;; When 'time' GET parameter is not specified, print the list of all available
	;; reports.
	(print-hourly-list))))

(define-report-handler (five-minute "/five-minute" "Five Minute Traffic")
    ((time :parameter-type 'integer))
  (with-periscope-page ("Five Minute Traffic Reports" :database t)
    (if time
	(let ((reports (load-reports :five-minute (simple-date:universal-time-to-timestamp time)))
	      previous-time next-time)
	  (htm
	   (:h2 "Five-Minute Report")
	   (if previous-time
	       (htm (:a :href (format nil "/hourly?time=~d" previous-time) "Previous Report"))
	       (htm "Previous Report"))
	   " | "
	   (:a :href "/hourly" "Back to all hourly reports")
	   " | "
	   (if next-time
	       (htm (:a :href (format nil "/hourly?time=~d" next-time) "Next Report"))
	       (htm "Next Report"))
	   (htm
	    (:div
	     :class "filter-list"
	     (:ul
	      (:li (:b "Filters"))
	      (loop
		 :for id = 0 :then (1+ id)
		 :for report in reports :do
		 (htm (:li (:a :href (format nil "javascript:displaySingleReport(~d);" id)
			       (str (filter-title (filter report))))))))
	     (:div :style "clear:both;")))
	   (loop
	      :for id = 0 :then (1+ id)
	      :for hidden = nil :then t
	      :for report in reports
	      :do (print-html report :id id :hidden hidden))))
	;; When 'time' GET parameter is not specified, print the list of all available
	;; reports.
	(print-report-list :five-minute))))


