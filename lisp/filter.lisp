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
   (active :col-type boolean :initarg :active :initform t
	   :accessor active-p)
   (string :col-type string
	   :initarg :string :type string
	   :initform (error "Must supply filter string!")
	   :reader filter-string)
   (internal-networks :initarg :internal-networks
		      :initform nil)
   (program :reader filter-program))
  (:metaclass pomo:dao-class)
  (:keys title))

(defmethod initialize-instance :after ((object filter) &key compile optimize)
  (when compile
    (compile-filter object optimize)))

(defmethod filter-title ((object filter))
  (title object))

(defmethod compile-filter ((object filter) &key optimize)
  "Compile the given Argus filter object and optionally optimize the resulting
filter program."
  ;; Hack (for now): ArgusFilterCompile crashes unless a global ArgusParserStruct
  ;; object has been set.  For now, before compiling, ensure we have initialized
  ;; a collector at least once.
  (unless *collector-init-p*
    (init-basic-collector))
  (with-slots (string program) object
    (let ((fprogram (%filter-compile string (if optimize 1 0))))
      (when (null-pointer-p fprogram)
	(filter-parse-error string))
      (setf program fprogram)
      (tg:finalize object (lambda () (%filter-free fprogram)))))
  object)

(defmethod compiled-p ((object filter))
  "Returns true if the filter has been compiled."
  (and (slot-boundp object 'program) (pointerp (filter-program object))))

(defmethod delete-filter ((object filter))
  (dolist (class '(host-stat traffic-stats service-traffic-stats))
    (execute (:delete-from (pomo:dao-table-name class)
			   :where (:= 'filter-id (filter-id object)))))
  (pomo:delete-dao object))

(defmethod print-object ((object filter) stream)
  (print-unreadable-object (object stream :type t)
    (format stream "\"~a\" (~:[not ~;~]compiled)"
	    (title object)
	    (compiled-p object))))

(defmethod filter= ((f1 filter) (f2 filter))
  "Compares two filters based on their database ID."
  (= (filter-id f1) (filter-id f2)))

(defun all-filters (&key compile (active-only t))
  "Returns all available filters."
  (let ((filters (if active-only
		     (pomo:select-dao 'filter (:= 'active t) 'title)
		     (pomo:select-dao 'filter t 'title))))
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

(define-easy-handler (edit-filters :uri "/filter-config") (error)
  (with-periscope-page ("Filter Configuration" :admin t :database t)
    (with-config-form ("/do-edit-filters" :onsubmit "return checkFilters()")
      (session-value-bind (new-title new-expr)
	(with-config-section ("Create New Filter")
	  (:table
	   (when (string= error "filter-exists")
	     (error-message
	      (format nil "A filter with the title ~a already exists!" new-title)))
	   (:tr (:td "Filter title")
		(:td (input "title" new-title)))
	   (when (string= error "bad-new-filter")
	     (error-message
	      (format nil "Syntax error in filter expression \"~a\"!" new-expr)))
	   (:tr (:td "Filter expression")
		(:td (input "expr" new-expr))))))
      
      (with-config-section ("Edit Available Filters")
	"Reports will not be generated for filters that are set to be <i>inactive</i>, but old data "
	"will remain available." (:br)
	(:i "Removing") " a filter will delete all reports associated with that filter!"
	(:div
	 :class "stats"
	 (:table
	  :id "available-filters"
	  (:tr (:th "Active") (:th "Title") (:th "Filter Expression") (:th "Remove"))
	  (loop :for filter :in (all-filters :active-only nil)
	     :for i = 0 :then (1+ i) :do
	     (with-slots (id title string) filter
	       (htm (:tr (:td (checkbox "active" :value id :checked (active-p filter) :index i))
			 (:td (input "edit-title" title :index i))
			 (:td (input "edit-expr" string :index i :size 50))
			 (:td (checkbox "remove" :value id :index i))))))))
	(:br)
	(delete-session-value 'new-title)
	(delete-session-value 'new-expr)
	(submit "Apply Configuration")))))

(define-easy-handler (do-edit-filters :uri "/do-edit-filters")
    (title expr
	   (remove :parameter-type 'array)
	   (active :parameter-type 'array)
	   (edit-title :parameter-type 'array)
	   (edit-expr  :parameter-type 'array))
  (declare (ignore edit-title edit-expr))
  (valid-session-or-lose :admin t)

  (let ((*redirect-page* "/filter-config"))
    (with-database ("periscope")
      (session-value-bind (new-expr new-title)
	(setf new-expr expr
	      new-title title)
	(unless (empty-string-p title)
	  (handler-case
	      (insert-dao (compile-filter (make-filter (escape-string title) expr)))
	    ;; Syntax error.
	    (parse-error ()
	      (error-redirect "bad-new-filter"))
	    ;; Filter with title exists.
	    (cl-postgres-error:unique-violation ()
	      (error-redirect "filter-exists")))))

    ;; TODO: This can be reduced from O(n^2) to O(n) with some work.
      (let ((all-filters (all-filters :active-only nil))
	    (active-filters (map 'list #'parse-integer (remove nil active))))
	(dolist (filter all-filters)
	  ;; If the filter is in the new "active list", it is supposed to be active.
	  (let ((active-p
		 (not (null (find (filter-id filter) active-filters)))))
	    ;; Don't set and commit the active column to the database unless it has
	    ;; changed.
	    (unless (eq active-p (active-p filter))
	      (setf (active-p filter) active-p)
	      (update-dao filter)))))

      (mapcar (lambda (id)
		(when id (delete-filter (find-filter id))))
	      (map 'list #'parse-integer (remove nil remove))))
    
    (delete-session-value 'new-expr)
    (delete-session-value 'new-title)
    (error-redirect "success")))

(define-easy-handler (filter-help :uri "/help-filter") ()
  (with-periscope-page ("Filter Syntax Help")
    (with-open-file (filter-syntax "filter.html" :direction :input)
      (loop
	 :for line = (read-line filter-syntax nil nil)
	 :while line :do
	 (write-line line *standard-output*)))))