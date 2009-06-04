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

(let ((flows 0))
  (defcallback receive-flow :void ((collector periscope-collector)
				   (type :uchar)
				   (record :pointer)
				   (dsrs :pointer))
    (declare (ignore collector record dsrs))
    (format t "FLOW (type ~a)~%" type)
    (incf flows)))

(defun test-argus ()
  (with-foreign-object (col 'periscope-collector)
    (periscope-collector-init col)
    (with-foreign-slots ((process_flow) (foreign-slot-value col 'periscope-collector 'callbacks)
			 periscope-callbacks)
      (setf process_flow (callback receive-flow)))
    (periscope-argus-local-add col "argus.1")
    (periscope-collector-start col)))
