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

(define-foreign-library libperiscope
  (:unix "/home/hbock/development/argus-periscope/periscope/.libs/libperiscope.so"))

(use-foreign-library libperiscope)

(defcstruct periscope-callbacks
  (idle :pointer)
  (process_flow :pointer)
  (input_complete :pointer))

(defcstruct periscope-collector
  (parser :pointer)
  (callbacks periscope-callbacks))

(defcfun "periscope_collector_init" :int
  (collector periscope-collector))

(defcfun "periscope_argus_local_add" :int
  (collector periscope-collector)
  (pathname :string))

(defcfun "periscope_collector_start" :void
  (collector periscope-collector))

(defcfun "periscope_collector_stop" :void
  (collector periscope-collector))

