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

(hunchentoot:define-easy-handler (sources :uri "/sources") ()
  (with-periscope-page ("Argus Input Sources")
    (:h3 "Manage Argus Input Sources")
    (unless (running-p *collector*)
      (who:htm
       "The collector is not running." (:br)))
    (:br)
    (cond
      ((null *collector*)
       (who:htm
	"WARNING: Collector not initialized."))
      ((null (remote-sources *collector*))
       (who:htm "No sources added!"))
      (t
       (who:htm
	(:table
	 (:tr (:th :colspan 3 "Remote Sources"))
	 (:tr (:th "Hostname") (:th "Status") (:th "Options"))	 
	 (dolist (source (remote-sources *collector*))
	   (who:htm
	    (:tr (:td (who:str (source-path source)))
		 (:td (who:str
		       (if (connected-p source)
			   "Connected"
			   "Not Connected")))
		 (:td
		  (:a :href (format nil "/sources?action=remove&source=~a" (source-path source))
		      "Remove")
		  (:a :href (format nil "/sources?action=connect&source=~a" (source-path source))
		      (who:str
		       (if (connected-p source)
			   "Disconnect"
			   "Connect")))))))))))))