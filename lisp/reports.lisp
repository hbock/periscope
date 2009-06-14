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
   (generated :reader generation-time :initform (get-universal-time))
   (handler :initarg :handler :initform nil)))

(defgeneric print-html (object &key)
  (:documentation "Print a report object in HTML format."))

(defmacro define-report ((type description) lambda-list &body body)
  `(progn
     (defun ,type (,@lambda-list)
       ,@body)

     (setf *report-list*
	   (delete-if (lambda (report) (eql (first report) (quote ,type))) *report-list*))
     (push (list (quote ,type) ,description) *report-list*)
     (push (hunchentoot:create-regex-dispatcher
	    ,(format nil "\/~a$" (string-downcase type)) (function ,type))
	   hunchentoot:*dispatch-table*)))
