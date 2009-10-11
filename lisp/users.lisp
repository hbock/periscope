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
  '(simple-array (unsigned-byte 8) (16)))

(defclass web-user ()
  ((id :col-type serial
       :reader user-id)
   (username :col-type string :initarg :username :type string
	     :accessor username)
   (display-name :col-type string :initarg :display-name
		 :accessor display-name)
   (title :initarg :title :accessor title)
   (password-hash :col-type string :initarg :password-hash
		  :accessor password-hash :initform nil)
   (admin :col-type boolean :initarg :admin-p
	  :accessor admin-p
	  :initform nil)
   (filters :col-type string :col-default "" :initarg :filters :initform ""
	    :accessor filters)
   (session :accessor session :initform nil))
  (:metaclass pomo:dao-class)
  (:keys username))

(defmethod initialize-instance :after ((user web-user) &key)
  (with-slots (filters) user
    ;; FIXME: This is a hack!
    ;; We explicitly establish another connection so we can query filter parameters
    ;; while querying user data.
    (with-database ("periscope")
      (setf filters (parse-integer-list filters "^(\\d,?)*$")))))

(defun load-users ()
  (clrhash *web-user-db*)
  (dolist (user (pomo:select-dao 'web-user))
    (setf (gethash (username user) *web-user-db*) user))
  t)

(defun save-users ()
  (maphash (lambda (un user)
	     (declare (ignore un))
	     (commit user)) *web-user-db*)
  t)

(defmethod commit ((user web-user) &key (save-method #'save-dao))
  (slot-let ((filters (format nil "~{~d~^,~}" filters))) user
    (funcall save-method user)))

(defmethod user-filters ((user web-user))
  "Returns a list of the filters assigned to user.  Unlike FILTERS, this function pulls
relevant information from the database."
  (when (filters user)
    (remove nil (mapcar #'find-filter (filters user)))))

;;; Not sure if this is needed on non-SBCL...
;;; Postmodern returns text fields as a string type that
;;; Lisp recognizes as a string, but MD5:MD5SUM-SEQUENCE
;;; does not, throwing a type error.
;;; To get around this, we import SB-MD5:MD5SUM-STRING on SBCL,
;;; and use MD5:MD5SUM-STREAM in combination with WITH-INPUT-FROM-STRING
;;; on other implementations.
;;; TODO: Test me on other implementations supported by MD5!
#-sbcl
(defun md5sum-string (string)
  (declare (type string string))
  (with-input-from-string (string-stream string)
      (md5:md5sum-stream string-stream)))

(defun hash-string (string)
  "Return the string representation of the 16-byte MD5 sum of string."
  (let ((sum (md5sum-string string)))
    (with-output-to-string (hash)
      (dotimes (i 16) (format hash "~2,'0x" (aref sum i))))))

(defun create-login (username password display-name &key (title "User") admin)
  "Create a web-user login.  The password may be a string or an array containing an
MD5 sum of a password.  If passed as a string, the password will be hashed and stored
as an MD5 sum."
  (handler-case
      (let ((user (make-instance 'web-user
				 :username username
				 :display-name display-name
				 :password-hash (hash-string password)
				 :title title
				 :admin-p admin)))
	(commit user :save-method #'insert-dao)
	(setf (gethash username *web-user-db*) user))
    (cl-postgres-error:unique-violation ()
      (periscope-config-error "Username ~a already exists." username))))

(defun user (&optional username)
  "Return the user with the given username, or if no parameter is provided, returns the currently
logged-in user.  If no user is logged in, returns NIL."
  (if username
      (gethash username *web-user-db*)
      (when (boundp 'hunchentoot:*session*)
	(let ((user (gethash (hunchentoot:session-value 'username) *web-user-db*)))
	  ;; If a session is bound to a particular user, but their session slot is NULL,
	  ;; we've got a problem - the user's session slot was nuked without the
	  ;; Hunchentoot SESSION being removed.  In this case, we SHOULD be able to
	  ;; silently remove this bound session and make things right again...
	  (if (and user (null (session user)))
	      (progn
		(hunchentoot:remove-session hunchentoot:*session*)
		;; Return NIL so we don't assert that user is ACTUALLY logged in.
		nil)
	      user)))))

(defun login-available-p ()
  "Return true if logins are available (i.e., at least one user login)."
  (plusp (hash-table-count *web-user-db*)))

(defun valid-session-p (&key admin)
  "Return true if the current Periscope login session exists and is valid."
  (let ((username (hunchentoot:session-value 'username))
	(userhash (hunchentoot:session-value 'userhash)))
    (when (and username userhash (string= userhash (hash-string username)))
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
       (unless (string= (hunchentoot:script-name hunchentoot:*request*) "/login")
	 (hunchentoot:redirect (format nil "/login?denied=login&redirect=~a"
				       (hunchentoot:script-name hunchentoot:*request*)))))
    
      ((and admin (not (admin-p (user))))
       (hunchentoot:redirect "/nowhere"))))
  t)

(defun user-count ()
  (hash-table-count *web-user-db*))

(defun user-list (&key logged-in-p)
  "Returns all users in the database. If LOGGED-IN-P is T, return only users who are
currently logged in."
  (loop :for username :being :the :hash-keys :in *web-user-db* :using (:hash-value user)
     :when (or (null logged-in-p) (logged-in-p user))
     :collect user))

(defun logout (&optional (user (user)))
  "Log out a particular user from the web interface; default is to log out the current user."
  (when (and user (session user))
    (hunchentoot:remove-session (session user))
    (setf (session user) nil)))

(defmethod logged-in-p ((user web-user))
  "Returns true if user is currently logged in to the web interface."
  (not (null (session user))))

(defun configure-p ()
  "Returns true when it is currently allowed to edit the configuration, meaning either there
are no users defined (anyone can edit) OR an administrator is currently logged in."
  (or (not (login-available-p)) (valid-session-p :admin t)))

(define-easy-handler (login :uri "/login")
    (denied redirect)
  
  ;; Don't allow access to the login page if there are no users, or if a user is already
  ;; logged in.
  (unless (and (null (user)) (login-available-p))
    (hunchentoot:redirect "/"))
  
  ;; Shadow *WEB-LOGIN-REQUIRED-P* to force the login page to be available even when
  ;; logins are required for all pages.  A bit of a hack...
  (with-periscope-page ("Login" :onload "loginFocus()")
    (string-case denied
      ("login" (warning-box (:p :class "denied" "You must be logged in to see this page.")))
      ("bad" (warning-box (:p :class "denied" "Invalid credentials. Please try again."))))
    (:br)
    (with-config-form ("/do-login")
      (with-config-section ("Log in to Periscope" "login")
	(:table
	 :class "login"
	 (:tr
	  (:td "Username")
	  (:td (input "username" "" :id "login")))
	 (:tr
	  (:td "Password")
	  (:td (password-input "password"))))
	(when (and denied redirect)
	  (hidden "redirect" (escape-string redirect)))
	(:input :type "submit" :value "Login")))))

(defun filter-selection (filters &key checked (start 0))
  (let ((i start))
    (with-html-output (*standard-output*)
      (:div
       :class "stats"
       (:table
	(:tr (:th :style "width:1em;" "Use") (:th "Title") (:th "Filter String"))
	(dolist (filter filters)
	  (htm
	   (:tr (:td (checkbox "filters" :value (filter-id filter) :checked checked :index i))
		(:td (str (filter-title filter)))
		(:td (str (filter-string filter)))))
	  (incf i)))))
    i))

(defun edit-user-form (title action &key user error new)
  (with-config-section (title action)
    (when new
      (htm (:span :class "success"
		  (fmt "User ~a added successfully!" (username user)))
	   (:br) (:br)))
    ;; Recover saved information, if available.
    (let ((username    (session-value 'conf-username))
	  (displayname (session-value 'conf-dispname))
	  (configp     (session-value 'conf-configp)))
      (htm
       (:table
	(:tr (:th :colspan 2 "Login Information") (:th))
	(string-case error
	  ("blankuser" (error-message "Username cannot be left blank."))
	  ("username" (error-message "Usernames must consist only of 
alphanumeric characters and underscores."))
	  ("userexists" (error-message (format nil "User '~a' already exists." username))))
	(if user
	    ;; Hidden parameter since we are editing an existing user.
	    (hidden "username" (username user))
	    ;; Otherwise we prompt for the username.
	    (htm
	     (:tr
	      (:td "Username")
	      (:td (input "username" username)))))
	(when (string= error "dispname")
	  (error-message "You must specify a display name (e.g., Don Schattle)."))
	(:tr
	 (:td "Display Name")
	 (:td (input "displayname" (if user (display-name user) displayname))))
	(string-case error
	  ("nopassword" (error-message "You must fill in BOTH password fields."))
	  ("passmatch" (error-message "Passwords do not match!")))
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
	 (:td (checkbox "configp" :checked (if user (admin-p user) configp)))))

       (let ((filters (when user (user-filters user)))
	     (start 0))
	 (when (and user filters)
	   (htm (:h3 "Current Filters"))
	   (setf start (filter-selection filters :checked t)))

	 (with-database ("periscope")
	   (let ((available-filters
		  (remove-if (lambda (filter) (member filter filters :test #'filter=))
			     (all-filters))))
	     (when available-filters
	       (htm (:h3 "Available Filters"))
	       (filter-selection available-filters :start start)))))))
    
    (:br)
    (submit "Apply Configuration")))

(define-easy-handler (edit-user :uri "/edit-user")
    (error user new add)
  (with-periscope-page ("Edit User" :admin t)
    (:p (:b (:a :href "/users" "Return to user login configuration")))
    (with-config-form ("/do-edit-user")
      (cond
	((and add (string= add "true"))
	 (hidden "action" "new")
	 (edit-user-form "Add New User" "newuser" :error error))

	(t
	 (hidden "action" "edit")
	 (let ((user (user user)))
	   (if user
	       (edit-user-form (format nil "Edit User (~a)" (username user)) "edituser"
			       :user user  :error error
			       :new (string= new "true"))
	       (hunchentoot:redirect "/users")))))
      
      ;; Delete no-longer-needed session values.
      (delete-session-value 'conf-username)
      (delete-session-value 'conf-dispname)
      (delete-session-value 'conf-configp)
      (delete-session-value 'conf-title)
      (delete-session-value 'conf-internal)
      (delete-session-value 'conf-subnet)
      (delete-session-value 'conf-vlan))))

;;; Errors:
;;;  - "username": Empty username.
;;;  - "dispname": Empty display name.
;;;  - "nopassword": Empty password field(s).
;;;  - "passmatch": Passwords don't match.
;;;  - "subnet": Invalid subnet specifier.
;;;  - "unadminself": Tried to remove administrator from own account.
(define-easy-handler (user-config :uri "/users") (error edit add)
  (with-periscope-page ("User Login Configuration" :admin t)
    (with-config-form ("/set-user-config")
      (with-config-section ("User Login Settings" "configure")
	(:table
	 (when (string= error "badsessiontime")
	   (error-message
	    (format nil "Invalid max session time.  Must be an integer greater than ~d seconds." +min-session-time+)))
	 (:tr
	  (:td "Maximum login session time (seconds)")
	  (:td (input "sessiontime" hunchentoot:*session-max-time*)))
	 (:tr
	  (:td "Require login for all pages")
	  (:td (checkbox "required" :checked *web-login-required-p*)))))

      (unless (login-available-p)
	(htm
	 (:p
	  (warning-box
	   (:big "No user logins defined." (:br)
		 (:a :href "/edit-user?add=true" "Click here to add a new user."))))))
      
      (when (login-available-p)
	(with-config-section ("User Logins" "manage")
	  (string-case error
	    ("unadminself"
	     (error-message "Error: You cannot remove administrator privileges from your own
account." :table nil))
	    ("success"
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
		  (:td (checkbox "delete" :index i :value "true"))))))
	   (:tr (:td :colspan 5
		     (:big (:b (:a :href "/edit-user?add=true" "Add a new user."))))))
	  (:br)
	  (submit "Apply Configuration"))))))

(defun process-login (user password)
  (let ((username (username user)))
    (when (string= (hash-string password) (password-hash user))
      (setf (session user) (hunchentoot:start-session)
	    (hunchentoot:session-value 'userhash) (hash-string username)
	    (hunchentoot:session-value 'username) username))))

(define-easy-handler (do-login :uri "/do-login")
    (username password redirect action)
  (flet ((bad-login () (hunchentoot:redirect "/login?denied=bad")))    
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
	(hunchentoot:redirect (if (login-required-p) "/login" "/")))))

(defun vlans-from-string (vlan-string)
  "Take a string of VLAN identifiers, separated by spaces and/or commas, and return a sorted list
of integers corresponding to these numbers.  Duplicate VLAN IDs are removed, and any invalid VLAN
IDs will signal a PARSE-ERROR."
  (parse-integer-list vlan-string "^(\\d{1,4}( *|(, *)))+$" (complement #'vlan-p)))

(define-easy-handler (set-user-config :uri "/set-user-config")
    (required
     (sessiontime :parameter-type 'integer)
     (user     :parameter-type 'array)
     (delete   :parameter-type 'array))
  (valid-session-or-lose :admin t)

  (let ((*redirect-page* "/users"))
    (when (or (null sessiontime)
	      (< sessiontime +min-session-time+))
      (error-redirect "badsessiontime"))
    
    (setf *web-login-required-p* (not (null required)))
    (when sessiontime
      (setf hunchentoot:*session-max-time* sessiontime))

    (loop
       :for i :from 0 :below (length user) :do
       (let ((u (user (aref user i))))
	 (cond
	   ((and (> (length delete) i) (aref delete i))
	    ;; If the user deletes a logged-in user, he must be logged off,
	    ;; so remove session before removing from the user cache
	    ;; and from the database.
	    (logout u)
	    (remhash (username u) *web-user-db*)
	    (pomo:delete-dao u))))))
    
  (save-config)
  (hunchentoot:redirect "/users?error=success"))

(define-easy-handler (do-edit-user :uri "/do-edit-user")
    (action username displayname password1 password2 configp
	    (internal :parameter-type 'array)
	    (filters :parameter-type 'array))
  (declare (ignore internal))
  (valid-session-or-lose :admin t)
  
  (let ((*redirect-page* "/edit-user")
	(user (user username)))

    (string-case action
      ;; Create a new login.
      ("new"
       (flet ((error-redirect (type &rest more-params)
		(apply #'error-redirect type :add "true" more-params)))

	 ;; retain add-user information in session, in the case of failure.
	 (setf (session-value 'conf-username) username
	       (session-value 'conf-dispname) (escape-string displayname)
	       (session-value 'conf-configp) (string= configp "configp"))

	 (when (user username)
	   (error-redirect "userexists"))
	 
	 (cond
	   ((empty-string-p username)
	    (error-redirect "blankuser"))
	   
	   ((not (ppcre:scan "^[A-Za-z0-9_]+$" username))
	    (error-redirect "username"))

	   ((empty-string-p displayname) (error-redirect "dispname"))

	   ((not (and password1 password2 (plusp (length password1)) (plusp (length password2))))
	    (error-redirect "nopassword"))
       
	   ((string/= password1 password2)
	    (error-redirect "passmatch")))

	 (handler-case
	     (let ((user
		    ;; If no users have been defined yet, the first user is automatically
		    ;; granted administrative privileges.
		    (create-login username password1 (escape-string displayname)
				  :admin (or (not (login-available-p))
					     (not (null configp))))))
	       ;; If this is the first user created - automatically log them in for convenience.
	       (when (= 1 (user-count))
		 (process-login user password1)))
	   (periscope-config-error () (error-redirect "userexists"))))
       (hunchentoot:redirect (format nil "/edit-user?user=~a&new=true" username)))
      
      ;; Edit an existing login.
      ("edit"
       (cond
	 ((null user)
	  (hunchentoot:redirect "/users"))

	 ((empty-string-p displayname)
	  (error-redirect "dispname" :user username))

	 ((and (not (empty-string-p password1 password2)) (string/= password1 password2))
	  (error-redirect "passmatch" :user username)))

       (handler-case
	   ;; Yo dawg, I herd you like map, so we put a MAPCAR in your MAPCAR
	   ;; in your MAP, so you can holy shit this is ridiculous.
	   (setf (filters user)
		 (mapcar #'filter-id
			 (remove nil
				 (mapcar #'find-filter
					 (map 'list #'parse-integer filters)))))
	 (parse-error () (hunchentoot:redirect "/users")))

       (if (and (null configp) (string= username (username (user))))
	   (error-redirect "unadminself")
	   (setf (admin-p user) (not (null configp))))

       (when (not (empty-string-p password1 password2))
	 (setf (password-hash user) (hash-string password1)))
      
       (setf (display-name user) (escape-string displayname))
       (commit user)))
      
    (save-config)
    (let ((*redirect-page* "/edit-user"))
      (error-redirect "success" :user (username user)))))