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
  ((title :initarg :title :reader filter-title :initform nil)
   (vlans :initarg :vlans :initform nil)
   (subnets :initarg :subnets :initform nil)
   (internal-networks :initarg :internal-networks :initform nil)
   (predicate :initarg :predicate :accessor filter-predicate
	      :initform (lambda (flow)
			  (declare (ignore flow)) t))))

(defun vlan-list-filter (vlans)
  (unless (every #'vlan-p vlans)
    (error "~a is not a valid VLAN ID!" (find-if-not #'vlan-p vlans)))
  (lambda (flow)
    (or (find (host-vlan (source flow)) vlans :test #'=)
	(find (host-vlan (dest flow))   vlans :test #'=))))

(defun subnet-list-filter (subnet*)
  (lambda (flow)
    (or
     (some (lambda (subnet)
	     (network-member-p (host-ip (source flow)) (car subnet) (cdr subnet))) subnet*)
     (some (lambda (subnet)
	     (network-member-p (host-ip (dest flow)) (car subnet) (cdr subnet))) subnet*))))

(defun make-generic-filter (title &key vlans subnets internal-networks)
  (let ((predicate
	 (cond ((not (or vlans subnets))
	(lambda (flow)
		  (declare (ignore flow)) t))
	       ((null subnets)
		(vlan-list-filter vlans))
	       ((null vlans)
		(subnet-list-filter subnets))
	       (t
		(let ((vlan-predicate (vlan-list-filter vlans))
		      (subnet-predicate (subnet-list-filter subnets)))
		  (lambda (flow)
		    (or (funcall vlan-predicate flow)
			(funcall subnet-predicate flow))))))))
    (make-instance 'filter :title title :vlans vlans :subnets subnets :predicate predicate
		   :internal-networks internal-networks)))

(defmethod print-config-forms ((object filter))
  (with-slots (vlans subnets internal-networks title) object
    `(make-generic-filter ,title :vlans (list ,@vlans)
			  :subnets ,(network-list-forms subnets)
			  :internal-networks ,(network-list-forms internal-networks))))

(defun apply-filters (sequence predicate-list &key key)
  "Apply each predicate in predicate-list once to each element in sequence, returning
one filtered list per predicate."
  (mapcar (lambda (predicate) (remove-if-not predicate sequence :key key)) predicate-list))

(defmethod print-html ((object filter) &key)
  (with-slots (title vlans subnets internal-networks) object
    (with-html-output (*standard-output*)
      (:div :class "filter-title"
	    (:big "Filter " (:b (str (filter-title object))))
	    (:br)
	    (:b "Internal Networks: ")
	    (fmt "~{~a~^, ~}"
		 (network-strings (if internal-networks
				      internal-networks
				      *internal-networks*)))
	    (:br) (:br)
	    (:i "Filter Parameters")
	    (:br)
	    (when vlans
	      (htm (:b "VLANs: ")
		   (fmt "~{~a~^, ~}" (mapcar #'vlan-name vlans))))
	    (:br)
	    (when subnets
	      (htm (:b "Subnets: ")
		   (fmt "~{~a~^, ~}" (network-strings subnets))))))))