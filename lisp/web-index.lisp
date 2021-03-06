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

(hunchentoot:define-easy-handler (index :uri "/") ()
  (with-periscope-page ("Home")
    (:h2 "Periscope Start Page")
    (warning-box
     "This is pre-release software.  Use at your own risk! "
     "Keep up-to-date with the latest releases "
     (:a :href "http://nautilus.oshean.org/wiki/Periscope" :target "_blank" "here."))
    (:br)
    (:table
     (:tr
      (:td
       :valign "top"
       (:b "View Traffic Reports")
       (:ul
	(:li (:a :href "/hourly" "Hourly traffic reports")
	     (let ((last (last-hourly-log)))
	       (when last
		 (htm
		  "[Last: "
		  (:a :href (format nil "/hourly?time=~d" (car last))
		      (str (date-string (universal-to-timestamp (car last)) :minutes t)))
		  "]"))))
	(:li "Daily traffic reports")
	(:li "Weekly traffic reports")))
      (when (login-available-p)
	(htm
	 (:td
	  :valign "top"
	  (:b (if (valid-session-p)
		  (fmt "User Session (Logged in as ~a)" (display-name (user)))
		  (str "User Session")))
	  (if (valid-session-p)
	      (let ((user (user)))
		(htm
		 (:ul (:li
		       (:a :href "/do-login?action=logout" "Log out of Periscope"))
		      (when (admin-p user)
			(htm (:li (:a :href (format nil "/edit-user?user=~a" (username user))
				      (fmt "Modify your account"))))))))
		   
	      (htm
	       (:ul
		(:li (:a :href "/login" "Login to Periscope")))))))))
     (:tr
      (when (configure-p)
	(htm
	 (:td
	  :valign "top"
	  (:b "Configure Periscope")
	  (:ul
	   (:li (:a :href "/periscope-config" "Manage Periscope settings"))
	   (:li (:a :href "/network-config" "Default network settings"))
	   (:li (:a :href "/users" "Manage user logins and filters"))
	   (when *web-show-diag*
	     (htm (:li (:a :href "/uuddlrlrbastart" "Diagnose problems with 
Periscope internals"))))))))
      ))))

(hunchentoot:define-easy-handler (about :uri "/about") ()
  (with-periscope-page ("About Periscope")
    (:h2 "About Periscope")
    (:p (:b "Periscope")
	"is a network conversation monitor inspired by the popular free-software project "
        (:a :href "http://ipaudit.sourceforge.net" "IPAudit.")
	"Periscope is written in C and Common Lisp. It is designed to be an integral part of OSHEAN's "
	(:a :href "http://nautilus.oshean.org/" "Nautilus")
        " system. Periscope monitors, logs, and analyzes network activity according to flows.")
    (:p "Periscope is built on top of the" (:a :href "http://qosient.com/argus" "Argus")
	"real-time flow monitor, developed by Carter Bullard of QoSient, LLC.")
    (:p "Periscope is " (:i "free software;") "it is licensed under the GNU GPLv2, and is free to study, modify, and "
        "redistribute. For more information, please visit the "
        (:a :href "http://nautilus.oshean.org/wiki/Periscope" "Nautilus wiki") "page on Periscope."

        (:p
         (:h3 "Core Developers")
         (:ul
          (:li "Harry Bock (OSHEAN)"))
	 (:h3 "Special Thanks")
	 (:ul
	  (:li "Carter Bullard (QoSient, LLC)"))))))

(defun web-default ()
  (with-periscope-page ("Page not found")
    (:h2 "Requested page not found!") (:br)
    (:p (:i "I'm sorry, Dave. I'm afraid I can't do that."))))

(setf hunchentoot:*default-handler* #'web-default)