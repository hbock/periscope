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

(defclass filter ()
  ((id :col-type serial
       :reader filter-id)
   (title :col-type string
	  :initarg :title :type string
	  :reader title)
   (string :col-type string
	   :initarg :string :type string
	   :initform (error "Must supply filter string!")
	   :reader filter-string)
   (internal-networks :initarg :internal-networks
		      :initform nil)
   (program :reader filter-program))
  (:metaclass pomo:dao-class)
  (:keys id))

(defmethod initialize-instance :after ((object filter) &key compile optimize)
  (when compile
    (compile-filter object optimize)))

(defmethod filter-title ((object filter))
  (title object))

(defmethod compile-filter ((object filter) &key optimize)
  "Compile the given Argus filter object and optionally optimize the resulting
filter program."
  (with-slots (string program) object
    (let ((fprogram (%filter-compile string (if optimize 1 0))))
      (when (null-pointer-p fprogram)
	(error "Syntax error in filter: ~a" string))
      (setf program fprogram)
      (tg:finalize object (lambda () (%filter-free fprogram))))))

(defmethod compiled-p ((object filter))
  "Returns true if the filter has been compiled."
  (and (slot-boundp object 'program) (pointerp (filter-program object))))

(defmethod print-object ((object filter) stream)
  (print-unreadable-object (object stream :type t)
    (format stream "\"~a\" (~:[not ~;~]compiled)"
	    (title object)
	    (compiled-p object))))

(defmethod filter= ((f1 filter) (f2 filter))
  "Compares two filters based on their database ID."
  (= (filter-id f1) (filter-id f2)))

(defun all-filters (&key compile)
  "Returns all available filters."
  (let ((filters (pomo:select-dao 'filter)))
    (when compile
      (dolist (filter filters)
	(compile-filter filter)))
    filters))

(defun find-filter (id)
  (first (pomo:select-dao 'filter (:= 'id id))))

(defmethod filter-match-p ((object filter) record-ptr)
  (plusp (%filter-record (foreign-slot-value
			  (filter-program object) 'argus-nff-program 'bf_insns) record-ptr)))

(defmethod make-filter ((title string) (filter-string string) &key internal-networks optimize)
  (make-instance 'filter :string filter-string :internal-networks internal-networks
		 :optimize optimize :title title))

(defmethod print-html ((object filter) &key)
  (with-slots (title string internal-networks) object
    (with-html-output (*standard-output*)
      (:div :class "filter-title"
	    (:h1 (str title))
	    (:b "Internal Networks: ")
	    (fmt "~{~a~^, ~}"
		 (network-strings (if internal-networks
				      internal-networks
				      *internal-networks*)))
	    (:br)
	    (:b "Filter string: ") (str string)))))

(define-easy-handler (show-filters :uri "/filters")
    (fid)
  (declare (ignore fid))
  (with-periscope-page ("Filter List" :admin t :database t)
    (:h2 "Filter List")
    (:div
     :class "stats"
     (:table
      (:tr (:th "ID") (:th "Title") (:th "Filter Expression"))
      (dolist (filter (all-filters))
	(with-slots (id title string) filter
	  (htm (:tr (:td (str id))
		    (:td (str title))
		    (:td (str string))))))))))