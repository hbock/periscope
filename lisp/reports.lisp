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

(defclass stats ()
  ((flows :initarg :flows :accessor flows :initform 0)
   (bytes :initarg :bytes :accessor bytes :initform 0)
   (packets :initarg :packets :accessor packets :initform 0)))

(defmethod add-stats ((object stats) &key (flows 1) (bytes 0) (packets 0))
  (incf (flows object) flows)
  (incf (bytes object) bytes)
  (incf (packets object) packets))

(defmethod print-html ((object stats) &key (title "General Stats") (with-row t) (flows t))
  (with-html-output (*standard-output*)
    (if with-row
	(htm
	 (:tr (:td (:b (str title)))
	      (:td (fmt "~:d" (packets object)))
	      (:td (str (byte-string (bytes object))))
	      (:td (fmt "~:d" (flows object)))))
	(htm
	 (:td (fmt "~:d" (packets object)))
	 (:td (str (byte-string (bytes object))))
	 (when flows
	   (htm (:td (fmt "~:d" (flows object)))))))))

(defgeneric print-html (object &key)
  (:documentation "Print a report object in HTML format."))

(defgeneric nadd (report flows)
  (:documentation "Add flow data to a given report."))

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

