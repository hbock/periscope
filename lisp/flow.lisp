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

(defclass flow ()
  ((ip-source :initarg :ip-source :reader flow-ip-source :initform (error "Must supply source IP!"))
   (ip-dest   :initarg :ip-dest   :reader flow-ip-dest :initform (error "Must supply destination IP!"))
   (protocol  :initarg :protocol  :reader flow-protocol :initform (error "Must supply IP protocol!"))
   (port-source :initarg :port-source :initform nil)
   (port-dest :initarg :port-dest :initform nil)))
