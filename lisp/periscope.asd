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
(in-package :cl-user)

(asdf:defsystem periscope
  :name "Periscope"
  :author "Harry Bock <harry@oshean.org>"
  :version "0.10.0-pre-alpha"
  :description "Network auditing tool"
  :depends-on (:cffi
	       :cl-fad
	       :cl-who
	       :cl-ppcre
	       :md5
	       :postmodern
	       :simple-date ; For PostgreSQL date compatibility
	       :local-time  ; DEPRECATED
	       :hunchentoot
	       :trivial-garbage
	       :bordeaux-threads)
  :serial t
  :components
  ((:file "packages")
   (:file "specials")
   (:file "conditions")
   (:file "config")
   ;; Foreign function interface for libperiscope/Argus
   (:file "periscope-cffi")
   (:file "argus-cffi")
   (:file "utility")
   ;; Core database support
   (:file "postmodern")
   (:file "collector")
   (:file "dns")
   ;; Central classes
   (:file "reports")
   (:file "flow")
   (:file "filter")
   (:file "time")
   (:file "argus-log")
   ;; Web interface
   (:file "web")
   (:file "web-index")
   (:file "web-config")
   (:file "web-utility")
   (:file "diagnostics")
   (:file "users")
   ;; Reports
   (:file "stats-general")
   (:file "stats-service")
   (:file "processing")
   (:file "report-handlers")
   ;; Entry point(s?)
   (:file "main")))