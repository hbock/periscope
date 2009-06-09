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

(hunchentoot:define-easy-handler (sources :uri "/config") (action source)
  (with-periscope-page ("Argus Input Sources")
    (:h2 "Periscope Control Panel")
    (:br)
    (unless *collector*
      (warning-box
	"Collector not initialized."))

    (when *collector*
      (unless (running-p *collector*)
	(if (string= action "run")
	    (run *collector*)
	    (warning-box
	      (who:htm
	       "The collector is not running." (:br)
	       (:b (:a :href "/config?action=run" "Click here to run the collector."))))))
      (who:htm (:br))

      (when (null (remote-sources *collector*))
	(warning-box
	  "No sources have been defined!"))

      (who:htm
       (:h3 "Add a source")
       (:form :action "config" :method "post"
	      (:label :for "hostname" "Hostname: ")
	      (:input :type "text" :size 20 :name "hostname")
	      (:input :type "submit" :value "Add")))
      (when (remote-sources *collector*)
	(who:htm
	 (:table
	  :class "sources"
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
		   (:a :href (format nil "/config?action=remove&source=~a" (source-path source))
		       "Remove")
		   (:a :href (format nil "/config?action=connect&source=~a" (source-path source))
		       (who:str
			(if (connected-p source)
			    "Disconnect"
			    "Connect")))))))))))))