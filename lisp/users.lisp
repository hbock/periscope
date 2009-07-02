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

(defclass web-user ()
  ((username :initarg :username :accessor username)
   (title :initarg :title :accessor title)
   (password-hash :accessor password-hash :initform nil)
   (privileges :accessor privileges)
   (session-id :accessor session-id)))

(defun hash-sequence (sequence)
  (md5:md5sum-sequence sequence))

(hunchentoot:define-easy-handler (login :uri "/login")
    (denied redirect)
  (with-periscope-page ("Login")
    (cond
      ((string= denied "login")
       (warning-box (:p :class "denied" "You must be logged in to see this page.")))
      ((string= denied "bad")
       (warning-box (:p :class "denied" "Invalid credentials. Please try again."))))
    (with-config-form ("/do-login" "Log in to Periscope" "login")
      (:table
       :class "input"
       (:tr
	(:td "Username")
	(:td (input "username" "")))
       (:tr
	(:td "Password")
	(:td (:input :type "password" :size 20))))
      (when (and denied redirect)
	(htm (:input :type "hidden" :name "redirect" :value redirect)))
      (:input :type "submit" :value "Login"))))

(hunchentoot:define-easy-handler (do-login :uri "/do-login")
    (username password redirect)
  (hunchentoot:redirect "/login?denied=bad"))