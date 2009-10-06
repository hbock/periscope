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

(define-report-handler (db-report-test "/db-test" "Database Report Test") ()
  (with-periscope-page ("Database Test")
    (with-database ("periscope")
      (htm
       (:div
	:class "filter-list"
	(:ul
	 (:li (:b "Filters"))
	 (loop
	    :for id = 0 :then (1+ id)
	    :for report in (reports *collector*) :do
	    (htm (:li (:a :href (format nil "javascript:displaySingleReport(~d);" id)
			  (str (filter-title (filter report))))))))
	(:div :style "clear:both;")))
      (loop
	 :for id = 0 :then (1+ id)
	 :for hidden = nil :then t
	 :for report in (reports *collector*)
	 :do (print-html report :id id :hidden hidden)))))
