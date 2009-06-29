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

(defun vlan-filter (vlan*)
  (etypecase vlan*
    (list
     (lambda (flow)
       (or (find (host-vlan (source flow)) vlan* :test #'=)
	   (find (host-vlan (dest flow))   vlan* :test #'=))))
    (vlan-id
     (lambda (flow)
       (or (= vlan* (host-vlan (source flow))) (= vlan* (host-vlan (dest flow))))))))

(defun netmask-filter (network netmask)
  (declare (type (unsigned-byte 32) network netmask))
  (lambda (flow)
    (or (network-member-p (host-ip (source flow)) network netmask)
	(network-member-p (host-ip (dest flow)) network netmask))))

(defun apply-filters (sequence predicate-list &key key)
  "Apply each predicate in predicate-list once to each element in sequence, returning
one filtered list per predicate."
  (mapcar (lambda (predicate) (remove-if-not predicate sequence :key key)) predicate-list))

(defun time-split (flow-sequence timestamp)
  (loop
     :for flow :in flow-sequence
     :if (local-time:timestamp< (start-time flow) timestamp)
     :collect flow :into before
     :else
     :collect flow :into after
     :finally (return (list before after))))