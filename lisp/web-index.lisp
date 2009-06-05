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
  (with-periscope-page ("Testing")
    (:h3 (who:fmt "Welcome to Periscope, version ~a!" *periscope-version*))
    "This is a pre-release version of what will eventually become Periscope 0.10.0, merged with
Argus client support.  For now, you should consider this release PRE-ALPHA software - it is
NOT meant for production use and will not be for some time; YMMV on any and all features within
this piece of software.  OSHEAN makes no guarantee to the functionality of this software at this
time."))

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