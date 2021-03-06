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

;;; Shamelessly adapted from Hunchentoot's conditions.lisp.
;;; Hunchentoot copyright notice:
;;; Copyright (c) 2008-2009, Dr. Edmund Weitz.  All rights reserved.

(define-condition periscope-condition (condition)
  ()
  (:documentation "Superclass for all conditions specific to Periscope."))

(define-condition periscope-error (periscope-condition error)
  ()
  (:documentation "Superclass for all errors specific to Periscope."))

(define-condition periscope-simple-error (periscope-error simple-condition)
  ()
  (:documentation "Periscope error class with formatting capabilities."))

(defun periscope-error (control &rest args)
  (error 'periscope-simple-error :format-control control :format-arguments args))

(define-condition periscope-config-error (periscope-simple-error)
  ()
  (:documentation "Error loading or saving Periscope's configuration."))

(defun periscope-config-error (control &rest args)
  (error 'periscope-config-error :format-control control :format-arguments args))

(define-condition periscope-file-error (periscope-simple-error file-error)
  ()
  (:documentation "Error handling files related to Periscope."))

(defun periscope-file-error (control &rest args)
  (error 'periscope-file-error :format-control control :format-arguments args))

(define-condition filter-parse-error (periscope-simple-error parse-error)
  ((error-type :initarg :error-type :reader filter-parse-error-type)
   (bad-data :initarg :bad-data :reader filter-parse-error-data))
  (:documentation "Specific error information about bad filter specifications.")
  (:report
   (lambda (condition stream)
     (format stream "Error parsing filter with bad ~a data: '~a' is not valid."
	     (filter-parse-error-type condition)
	     (filter-parse-error-data condition)))))

(defun filter-parse-error (type data)
  (error 'filter-parse-error :error-type type :bad-data data))

(define-condition operation-not-implemented (periscope-error)
  ((operation :initarg :operation
	      :reader operation-not-implemented-operation
	      :documentation "The name of the unimplemented operation."))
  (:report (lambda (condition stream)
	     (format stream "The operation ~A is not yet implemented for the Lisp implementation
~A, version ~A."
		     (operation-not-implemented-operation condition)
		     (lisp-implementation-type)
		     (lisp-implementation-version)))))

(defun not-implemented (name)
  (error 'operation-not-implemented :operation name))