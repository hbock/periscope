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
   (display-name :initarg :real-name :accessor display-name)
   (title :initarg :title :accessor title)
   (password-hash :initarg :password-hash :accessor password-hash :initform nil)
   (privileges :accessor privileges :initform nil)
   (filters :accessor filters :initform nil)
   (session-id :accessor session-id)))

(defun hash-sequence (sequence)
  (md5:md5sum-sequence sequence))

(defun create-login (username password &key (title "User"))
  (multiple-value-bind (user existsp)
      (gethash username *web-user-db*)
    (declare (ignore user))
    (if existsp
	(error "Username ~a already exists." username)
	(let ((user (make-instance 'web-user
				   :username username
				   :password-hash (hash-sequence password)
				   :title title)))
	  (setf (gethash username *web-user-db*) user)))))

(defun user (&optional username)
  (if username
      (gethash username *web-user-db*)
      (first (user-list))))

(defun login-available-p ()
  (plusp (hash-table-count *web-user-db*)))

(defun valid-session-p ()
  (let ((username (hunchentoot:session-value 'username))
	(userhash (hunchentoot:session-value 'userhash)))
    (when (and username userhash (equalp userhash (hash-sequence username)))
      (multiple-value-bind (user existsp)
	  (gethash username *web-user-db*)
	(and existsp (not (null (session-id user))))))))

(defun login-required-p ()
  "Returns true if logins are generally required to access the Periscope web interface."
  (and *web-login-required-p*
       (not (zerop (hash-table-count *web-user-db*)))))

(defun user-list ()
  "Returns all users in the database."
  (loop :for username :being :the :hash-keys :in *web-user-db* :using (:hash-value user)
     :collect user))

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
	(:td (:input :type "password" :name "password" :size 20))))
      (when (and denied redirect)
	(htm (:input :type "hidden" :name "redirect" :value redirect)))
      (:input :type "submit" :value "Login"))))

(hunchentoot:define-easy-handler (do-login :uri "/do-login")
    (username password redirect action)
  (flet ((bad-login () (hunchentoot:redirect "/login?denied=bad"))
	 (process-login (user password)
	   (when (equalp (hash-sequence password) (password-hash user))
	     (setf (session-id user) (hunchentoot:next-session-id *web-server*)) 
	     (hunchentoot:start-session)
	     (setf (hunchentoot:session-value 'userhash) (hash-sequence username)
		   (hunchentoot:session-value 'username) username))))
    
    (cond
      ((valid-session-p)
       (if (string= action "logout")
	   (progn
	     (setf (session-id (user)) nil)
	     (hunchentoot:reset-sessions))
	   (hunchentoot:redirect "/")))
      
      ((and username password (login-available-p))
       (let ((user (user username)))
	 (if user
	     (unless (process-login user password)
	       (bad-login))
	     (bad-login)))))

    (if (and redirect (valid-session-p))
	(hunchentoot:redirect redirect)
	(hunchentoot:redirect "/"))))
