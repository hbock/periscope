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

(hunchentoot:define-easy-handler (service-names :uri "/service-names") ()
  (when (zerop (hash-table-count *service-cache*))
    (create-service-cache))

  (with-periscope-page ("DARPA Internet Service Names")
    (:h2 "Table of DARPA Internet Service Names")
    (:p "As specified in the system services file.")

    (:table
     :class "sources"
     (:tr (:th "Port Number") (:th "TCP Service") (:th "UDP Service"))
     (loop :for port :being :the :hash-keys :in *service-cache* :using (:hash-value names) :do
	(htm (:tr (:td (str port)) (:td (str (car names))) (:td (str (cdr names)))))))))
