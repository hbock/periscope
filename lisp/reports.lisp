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

(defclass report ()
  ((generated :reader generation-time :initform (now))
   (format-version :reader report-format-version)))

(defgeneric print-html (object &key)
  (:documentation "Print a report object in HTML format."))

(defun report-handlers (request)
  "Handle Periscope-specific report requests. Returns the report's handler function as
defined using DEFINE-REPORT-HANDLER."
  (loop :for (symbol uri desc handler) :in *report-handler-list*
     :when (string-equal (hunchentoot:script-name request) uri)
     :do (return handler)))

(defmacro define-report-handler ((type uri description) lambda-list &body body)
  "Define a Periscope report page as if by DEFUN."
  `(prog1
       (defun ,type (&key ,@(loop :for part :in lambda-list :collect
			       (hunchentoot::make-defun-parameter part 'string :get)))
	 ,@body)

     (setf *report-handler-list*
	   (delete-if (lambda (report)
			(or (eql (first report) (quote ,type))
			    (string-equal (second report) ,uri)))
		      *report-handler-list*))
     (unless (find #'report-handlers hunchentoot:*dispatch-table*)
       (push #'report-handlers hunchentoot:*dispatch-table*))
     (push (list (quote ,type) ,uri ,description (function ,type)) *report-handler-list*)))

(defun in-report-directory (filespec &optional (directory *report-directory*))
  (ensure-directories-exist (merge-pathnames filespec directory)))

(defun hourly-log (time &optional (directory *report-directory*))
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
