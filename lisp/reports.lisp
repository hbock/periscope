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
  ((time :reader report-time :initform (get-universal-time))
   (generated :reader generation-time :initform (get-universal-time))))

(defgeneric print-html (object &key)
  (:documentation "Print a report object in HTML format."))

(defun report-handlers (request)
  "Handle Periscope-specific report requests. Returns the report's handler function as
defined using DEFINE-REPORT-HANDLER."
  (loop :for (uri desc handler) :in *report-handler-list*
     :when (string= (hunchentoot:script-name request) (format nil "/~a" uri))
     :do (return handler)))

(defmacro define-report-handler ((type description) lambda-list &body body)
  "Define a Periscope report page as if by DEFUN."
  `(progn
     (defun ,type (,@lambda-list)
       ,@body)

     (setf *report-handler-list*
	   (delete-if (lambda (report) (eql (first report) (quote ,type))) *report-handler-list*))
     (unless (find #'report-handlers hunchentoot:*dispatch-table*)
       (push #'report-handlers hunchentoot:*dispatch-table*))
     (push (list (quote ,type) ,description (function ,type)) *report-handler-list*)))
