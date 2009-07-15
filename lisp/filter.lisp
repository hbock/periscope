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
   (predicate :initarg :predicate :accessor filter-predicate
	      :initform (lambda (flow)
			  (declare (ignore flow)) t))))

(defun valid-vlan-p (vlan)
  (typep vlan 'vlan-id))

(defun vlan-filter (&rest vlan*)
  (cond
    ((null (cdr vlan*))
     (let ((vlan (car vlan*)))
       (lambda (flow)
	 (or (= vlan (host-vlan (source flow)))
	     (= vlan (host-vlan (dest flow)))))))
    (t
     (lambda (flow)
       (or (find (host-vlan (source flow)) vlan* :test #'=)
	   (find (host-vlan (dest flow))   vlan* :test #'=))))))

(defun subnet-filter (&rest subnet*)
  (lambda (flow)
    (or
     (some (lambda (subnet)
	     (network-member-p (host-ip (source flow)) (car subnet) (cdr subnet))) subnet*)
     (some (lambda (subnet)
	     (network-member-p (host-ip (dest flow)) (car subnet) (cdr subnet))) subnet*))))

(defun apply-filters (sequence predicate-list &key key)
  "Apply each predicate in predicate-list once to each element in sequence, returning
one filtered list per predicate."
  (mapcar (lambda (predicate) (remove-if-not predicate sequence :key key)) predicate-list))

(defun time-split (flow-sequence)
  (flet ((%time-split (flow-sequence timestamp)
	   (loop
	      :for flow :in flow-sequence
	      :if (timestamp< (start-time flow) timestamp)
	      :collect flow :into before
	      :else
	      :collect flow :into after
	      :finally (return (list before after)))))
    (let (split-list)
      (do* ((time (timestamp+
		   (timestamp-minimize-part (start-time (first flow-sequence)) :min) 10 :minute)
		  (timestamp+ time 10 :minute))
	    (split (%time-split flow-sequence time)
		   (%time-split (second split) time)))
	   ((and (null (car split)) (null (second split)))	    
	    split-list)
	(when (car split)
	  (push (first split) split-list))))))

(defmacro make-filter ((title) &body filters)
  (let (vlans subnets)
    (loop :for filter-desc :in filters :do
       (ecase (first filter-desc)
	 (:vlan
	  (loop :for vlan :in (rest filter-desc) :do
	     (if (valid-vlan-p vlan)
		 (push vlan vlans)
		 (error "~a is not a valid VLAN identifer!" vlan))
	     :finally (setf vlans (sort vlans #'<))))
	 (:subnet
	  (loop :for (network netmask) :in (rest filter-desc) :do
	     (push `(cons ,network ,netmask) subnets)
	     :finally (setf subnets (nreverse subnets))))))
    `(make-instance 'filter :title ,title :vlans (list ,@vlans) :subnets (list ,@subnets)
		    :predicate (lambda (flow)
				 (or (funcall (apply #'vlan-filter (list ,@vlans)) flow)
				     (funcall (apply #'subnet-filter (list ,@subnets)) flow))))))

