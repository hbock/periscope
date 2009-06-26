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
       (with-slots (vlan-source vlan-dest) flow
	 (or (find vlan-source vlan* :test #'=)
	     (find vlan-dest vlan* :test #'=)))))
    (vlan-id
     (lambda (flow)
       (with-slots (vlan-source vlan-dest) flow
	 (or (= vlan* vlan-source) (= vlan* vlan-dest)))))))

(defun netmask-filter (network netmask)
  (declare (type (unsigned-byte 32) network netmask))
  (lambda (flow)
    (with-slots (ip-source ip-dest) flow
      (or (network-member-p ip-source network netmask)
	  (network-member-p ip-dest network netmask)))))

(defun apply-filters (sequence predicate-list &key key)
  "Apply each predicate in predicate-list once to each element in sequence, returning
one filtered list per predicate."
  (mapcar (lambda (predicate) (remove-if-not predicate sequence :key key)) predicate-list))
