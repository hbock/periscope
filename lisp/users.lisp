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

(deftype md5sum ()
  '(simple-vector 16))

(defclass web-user ()
  ((username :initarg :username :accessor username)
   (display-name :initarg :display-name :accessor display-name)
   (title :initarg :title :accessor title)
   (password-hash :initarg :password-hash :accessor password-hash :initform nil)
   (admin :initarg :admin-p :accessor admin-p :initform nil)
   (filters :accessor filters :initform nil)
   (session :accessor session :initform nil)))

(defmethod filter-predicates ((user web-user))
  "Return all filter predicates defined for user."
  (mapcar #'filter-predicate (filters user)))

(defun hash-sequence (sequence)
  "Return the 16-byte MD5 sum of sequence.  Essentially a wrapper around MD5:MD5SUM-SEQUENCE."
  (md5:md5sum-sequence sequence))

(defun create-login (username password display-name &key (title "User") admin)
  "Create a web-user login.  The password may be a string or an array containing an
MD5 sum of a password.  If passed as a string, the password will be hashed and stored
as an MD5 sum."
  (multiple-value-bind (user existsp)
      (gethash username *web-user-db*)
    (declare (ignore user))
    (if existsp
	(error "Username ~a already exists." username)
	(let ((user (make-instance 'web-user
				   :username username
				   :display-name display-name
				   :password-hash
				   (etypecase password
				     (string (hash-sequence password))
				     (md5sum password))
				   :title title
				   :admin-p admin)))
	  (setf (gethash username *web-user-db*) user)))))

(defun user (&optional username)
  "Return the user with the given username, or if no parameter is provided, returns the currently
logged-in user.  If no user is logged in, returns NIL."
  (if username
      (gethash username *web-user-db*)
      (when (boundp 'hunchentoot:*session*)
	(gethash (hunchentoot:session-value 'username) *web-user-db*))))

(defun login-available-p ()
  "Return true if logins are available (i.e., at least one user login)."
  (plusp (hash-table-count *web-user-db*)))

(defun valid-session-p (&key admin)
  "Return true if the current Periscope login session exists and is valid."
  (let ((username (hunchentoot:session-value 'username))
	(userhash (hunchentoot:session-value 'userhash)))
    (when (and username userhash (equalp userhash (hash-sequence username)))
      (multiple-value-bind (user existsp)
	  (gethash username *web-user-db*)
	(and existsp (not (null (session user))) (or (not admin) (admin-p user)))))))

(defun login-required-p ()
  "Returns true if logins are generally required to access the Periscope web interface."
  (and *web-login-required-p* (login-available-p)))

(defun valid-session-or-lose (&key admin)
  "If logins are required and no valid session is available, redirect to the login page."
  (when (login-available-p)
    (cond
      ((not (valid-session-p))
       (hunchentoot:redirect (format nil "/login?denied=login&redirect=~a"
				     (hunchentoot:script-name hunchentoot:*request*))))
    
      ((and admin (not (admin-p (user))))
       (hunchentoot:redirect "/nowhere"))))
  t)

(defun user-list ()
  "Returns all users in the database."
  (loop :for username :being :the :hash-keys :in *web-user-db* :using (:hash-value user)
     :collect user))

(defun logout (&optional (user (user)))
  "Log out a particular user from the web interface; default is to log out the current user."
  (when (and user (session user))
    (hunchentoot:remove-session (session user))
    (setf (session user) nil)))

(defmethod logged-in-p ((user web-user))
  "Returns true if user is currently logged in to the web interface."
  (not (null (session user))))

(defun create-login-forms (&optional (db *web-user-db*))
  "Output forms that, when evaluated, re-create the web user database (for configuration purposes)."
  `(progn
     ,@(loop :for username :being :the :hash-keys :in db :using (:hash-value user) :collect
	  `(create-login ,username ,(password-hash user) ,(display-name user)
			 :admin ,(admin-p user)))))

(defmethod create-filter-forms ((user web-user))
  "Output forms that, when evaluated, set up the users' flow filters exactly as they are
currently set up (for configuration purposes)."
  (when (filters user)
    `(setf (filters (user ,(username user)))
	   (list
	    ,@(loop :for filter :in (filters user) :collect
		 (with-slots (vlans subnets title) filter
		   `(make-filter (,title)
		      ,(when vlans `(:vlan ,@vlans))
		      ,@(when subnets
			      `((:subnet
				 ,@(loop :for (network . netmask) :in subnets :collect
				      `(,network ,netmask))))))))))))

(hunchentoot:define-easy-handler (login :uri "/login")
    (denied redirect)
  
  ;; Don't allow access to the login page if there are no users, or if a user is already
  ;; logged in.
  (unless (and (null (user)) (login-available-p))
    (hunchentoot:redirect "/"))
  
  ;; Shadow *WEB-LOGIN-REQUIRED-P* to force the login page to be available even when
  ;; logins are required for all pages.  A bit of a hack...
  (let ((*web-login-required-p* nil))
    (with-periscope-page ("Login")
      (cond
	((string= denied "login")
	 (warning-box (:p :class "denied" "You must be logged in to see this page.")))
	((string= denied "bad")
	 (warning-box (:p :class "denied" "Invalid credentials. Please try again."))))
      (:br)
      (with-config-form ("/do-login" "Log in to Periscope" "login")
	(:table
	 :class "login"
	 (:tr
	  (:td "Username")
	  (:td (input "username" "")))
	 (:tr
	  (:td "Password")
	  (:td (password-input "password"))))
	(when (and denied redirect)
	  (htm (:input :type "hidden" :name "redirect" :value redirect)))
	(:input :type "submit" :value "Login")))))


(defun edit-user-form (title action &key user error new)
  (with-config-form ("/set-user-config" title action)
    (when new
      (htm (:p :class "success"
	       (fmt "User ~a added successfully! You may add traffic filters for this user
below." (username user)))))
    (:table
     (:tr (:th :colspan 2 "Login Information") (:th))
     (when (string= error "username")
       (error-message "You must specify a username."))
     (if user
	 (htm (:input :type "hidden" :name "username" :value (username user)))
	 (htm
	  (:tr
	   (:td "Username")
	   (:td (input "username" "")))))
     (when (string= error "dispname")
       (error-message "You must specify a display name (e.g., Don Schattle)."))
     (:tr
      (:td "Display Name")
      (:td (input "displayname" (if user (display-name user) ""))))
     (cond ((string= error "nopassword")
	    (error-message "You must fill in BOTH password fields."))
	   ((string= error "passmatch")
	    (error-message "Passwords do not match!")))
     (:tr
      (:td "Password")
      (:td (password-input "password1")))
     (:tr
      (:td "Password (re-type)")
      (:td (password-input "password2")))
     (when (string= error "unadminself")
       (error-message "You can not remove administrator privileges from your own account!"))
     (:tr
      (:td "Administrator privileges")
      (:td (checkbox "configp" :checked (when user (admin-p user)))))
     (:tr (:th :colspan 2 (str (if user "Add new filter:" "Initial traffic filter:"))))
     (:tr
      (:td "Filter Title")
      (:td (input "title[0]" "" :size 30)))
     (:tr
      (:td "Subnet Filter (CIDR notation)")
      (:td (input "subnet[0]" "" :size 30)))
     (:tr
      (:td "VLAN Filter")
      (:td (input "vlan[0]" "" :size 30)))
     
     (when (string= error "subnet")
       (error-message "Invalid CIDR network specification!"))
     (when (and user (filters user))
       (flet ((print-vlans (filter)
		(format nil "~{~a~^, ~}" (slot-value filter 'vlans)))
	      (print-subnets (filter)
		(format nil "~{~a~^, ~}"
			(mapcar (lambda (subnet)
				  (ip-string (car subnet) (cdr subnet)))
				(slot-value filter 'subnets)))))
	 (htm
	  (:tr (:th :colspan 2 "Edit Filters"))
	  (:tr
	   (:td
	    :colspan 3
	    (:table
	     :class "input"
	     (:tr (:th "Title") (:th "Subnet Filters") (:th "VLAN filters") (:th "Delete"))
	     (loop :for i = 1 :then (1+ i)
		:for filter :in (filters user) :do
		(htm
		 (:tr
		  (:td (input "title" (filter-title filter) :index i :size 30))
		  (:td (input "subnet" (print-subnets filter) :index i :size 30))
		  (:td (input "vlan" (print-vlans filter) :index i :size 30))
		  (:td (checkbox "delete" :index i))))))))))))
    (:br)
    (submit "Commit Changes")))

(hunchentoot:define-easy-handler (edit-user :uri "/edit-user") (error user new)
  (with-periscope-page ("Edit User" :admin t)
    (let ((user (user user)))
      (if user
	  (edit-user-form (format nil "Edit User [~a]" (username user)) "edituser"
			  :user user :error error :new (string= new "true"))
	  (hunchentoot:redirect "/users")))))

;;; Errors:
;;;  - "username": Empty username.
;;;  - "dispname": Empty display name.
;;;  - "nopassword": Empty password field(s).
;;;  - "passmatch": Passwords don't match.
;;;  - "subnet": Invalid subnet specifier.
;;;  - "unadminself": Tried to remove administrator from own account.
(hunchentoot:define-easy-handler (user-config :uri "/users") (error edit add)
  (with-periscope-page ("User Login Configuration" :admin t)
    (with-config-form ("/set-user-config" "Login Configuration" "configure")
      (:table
       (:tr
	(:td "Require login for all pages")
	(:td (checkbox "required" :checked *web-login-required-p*))))
      (:br)
      (:input :type "submit" :value "Apply Configuration"))

    (when (login-available-p)
      (with-config-form ("/set-user-config" "User Logins" "manage")
	(cond
	  ((string= error "unadminself")
	   (error-message "Error: You cannot remove administrator privileges from your own
account." :table nil))
	  ((and (string= error "success"))
	   (cond
	     ((not (empty-string-p edit))
	      (htm (:p (:b (fmt "Edited user '~a' successfully!" edit)))))
	     ((not (empty-string-p add))
	      (htm (:p (:b (fmt "Added new user '~a' successfully!" add))))))))
	(:table
	 :class "input"
	 (:tr (:th "Username ") (:th "Display Name") (:th "Administrator")
	      (:th "Edit User") (:th "Remove User"))
	 (loop
	    :for i = 0 :then (1+ i)
	    :for user :in (user-list) :do
	    (let ((username (username user)))
	      (htm
	       (:tr
		(:td
		 (:b (str username))
		 (hidden "user" username :index i))
		(:td (str (display-name user)))
		(:td (str (if (admin-p user) "Yes" "No")))
		(:td (:a :href (format nil "/edit-user?user=~a" username) "Edit"))
		(:td (checkbox "delete" :index i :value "true")))))))
	(:br)
	(:input :type "submit" :value "Apply Configuration")))

    (edit-user-form "Add New User" "newuser" :error error)))

(hunchentoot:define-easy-handler (do-login :uri "/do-login")
    (username password redirect action)
  (flet ((bad-login () (hunchentoot:redirect "/login?denied=bad"))
	 (process-login (user password)
	   (when (equalp (hash-sequence password) (password-hash user))
	     (setf (session user) (hunchentoot:start-session))
	     (setf (hunchentoot:session-value 'userhash) (hash-sequence username)
		   (hunchentoot:session-value 'username) username))))
    
    (cond
      ((valid-session-p)
       (if (string= action "logout")
	   (logout)
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

(defun vlans-from-string (vlan-string)
  "Take a string of VLAN identifiers, separated by spaces and/or commas, and return a sorted list
of integers corresponding to these numbers.  Duplicate and invalid VLAN IDs are removed."
  (parse-integer-list vlan-string (lambda (vlan) (or (zerop vlan) (> vlan 4095)))))

(hunchentoot:define-easy-handler (set-user-config :uri "/set-user-config")
    (action username displayname password1 password2 configp
	    required
	    (user   :parameter-type 'array)
	    (delete :parameter-type 'array)
	    (title :parameter-type 'array)
	    (subnet :parameter-type 'array)
	    (vlan   :parameter-type 'array))
  (valid-session-or-lose :admin t)

  (let ((*redirect-page* "/users"))
    (cond
      ((string= action "configure")
       (setf *web-login-required-p* (not (null required))))

      ((string= action "manage")
       (loop
	  :for i :from 0 :below (length user) :do
	  (let ((u (user (aref user i))))
	    (cond
	      ((and (> (length delete) i) (aref delete i))
	       ;; If the user deletes a logged-in user, he must be logged off,
	       ;; so remove session.
	       (logout u)
	       (remhash (username u) *web-user-db*))))))

      ((string= action "newuser")
       (cond
	 ((empty-string-p username) (error-redirect "username"))
	 ((empty-string-p displayname) (error-redirect "dispname"))

	 ((not (and password1 password2 (plusp (length password1)) (plusp (length password2))))
	  (error-redirect "nopassword"))
       
	 ((string/= password1 password2)
	  (error-redirect "passmatch"))
       
	 ((and subnet (plusp (length subnet)))
	  (handler-case
	      (parse-ip-string subnet)
	    (parse-error (e)
	      (declare (ignore e))
	      (error-redirect "subnet")))))
       
       (create-login username password1 displayname :admin (not (null configp)))
       (hunchentoot:redirect (format nil "/edit-user?user=~a&new=true" username)))))
  
  (when (string= action "edituser")
    (let ((*redirect-page* "/edit-user")
	  (user (user username)))
      (cond
	((null user)
	 (hunchentoot:redirect "/users"))

	((empty-string-p displayname)
	 (error-redirect "dispname" :user username))

	((and (not (empty-string-p password1 password2)) (string/= password1 password2))
	 (error-redirect "passmatch" :user username))

	((/= (length title) (length subnet) (length vlan))
	 (hunchentoot:redirect (format nil "/edit-user?user=~a" username)))

	((some #'empty-string-p title)
	 (error-redirect "badtitle" :filter (position-if #'empty-string-p title))))

      (if (and (null configp) (string= username (username (user))))
	  (error-redirect "unadminself")
	  (setf (admin-p user) (not (null configp))))

      (when (not (empty-string-p password1 password2))
	(setf (password-hash user) (hash-sequence password1)))
      
      (setf (display-name user) displayname)
       
      (loop :for i :from 0 :below (length title) :do
	 (let ((vlans (vlans-from-string (aref vlan i)))
	       subnets)
	   (push
	    (make-instance 'filter
			   :title (aref title i) :vlans vlans
			   :predicate (vlan-list-filter vlans))
	    (filters user))))
      
      (save-config)
      (let ((*redirect-page* "/edit-user"))
	(error-redirect "success" :user (username user)))))
  
  (save-config)
  (hunchentoot:redirect "/users?error=success"))