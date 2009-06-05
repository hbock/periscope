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

(defclass collector ()
  ((ptr :initform nil :accessor get-ptr)))

(defmethod initialize-instance :after ((object collector) &key)
  (let ((ptr (foreign-alloc 'periscope-collector)))
    (setf (get-ptr object) ptr)
    (when (minusp (%collector-init ptr))
      (foreign-free ptr)
      (error "Unable to initialize collector!"))
    #+sbcl (sb-ext:finalize object (lambda ()
				     (%collector-free ptr)
				     (foreign-free ptr)))))

(defmethod start ((object collector))
  (%collector-start (get-ptr object)))

(defmethod stop ((object collector))
  (%collector-stop (get-ptr object)))