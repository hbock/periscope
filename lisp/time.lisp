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

(deftype universal-time () '(integer 536870912))
(defparameter +month-days+
    #(0 31 28 31 30 31 30 31 31 30 31 30 31))

(defun leap-year-p (year)
  "Returns true if year is a leap year."
  (and (zerop (mod year 4))
       (or (zerop (mod year 400))
           (not (zerop (mod year 100))))))

(defun month-days (month year)
  (declare (type (integer 1 12) month))
  (if (and (= month 2) (leap-year-p year))
      29
      (aref +month-days+ month)))

(defun normalize-hour (hour)
  (mod hour 24))

(defun normalize-day (day month year)
  (declare (type (integer 1 12) month))
  (if (plusp day)
      (let ((month-days (month-days month year)))
	(if (> day month-days) (mod day month-days) day))
      (let ((month-days (month-days
			 (normalize-month (1- month)) year)))
	(+ month-days day))))

(defun normalize-month (month)
  "Returns a corrected month (1 - 12) given an integer from -11 to 23."
  (declare (type (integer -11 23)))
  (cond
    ((plusp month)
     (if (> month 12) (mod month 12) month))
    (t (+ 12 (1- month)))))

(defmacro define-time-method (name (time-var &rest lambda-rest) vars &body body)
  `(eval-when (:compile-toplevel :load-toplevel :execute)
     (defmethod ,name ((,time-var integer) ,@lambda-rest)
       (multiple-value-bind (,@vars)
	   (decode-universal-time ,time-var)
	 ,@body))
     
     (defmethod ,name ((,time-var timestamp) ,@lambda-rest)
       (universal-to-timestamp (,name (timestamp-to-universal ,time-var) ,@lambda-rest)))))

(define-time-method this-half-hour (time)
    (sec min hour date month year)
  (declare (ignore sec))
  (encode-universal-time 0 (if (>= min 30) 30 0) hour date month year))

(define-time-method next-half-hour (time)
    (sec min hour date month year)
  (declare (ignore sec))
  (let* ((new-min (if (>= min 30) 0 30))
	 (new-hour (normalize-hour (if (< new-min min) (1+ hour) hour)))
	 (new-date (normalize-day (if (< new-hour hour) (1+ date) date) month year))
	 (new-month (normalize-month (if (< new-date date) (1+ month) month)))
	 (new-year (if (< new-month month) (1+ year) year)))
    (encode-universal-time 0 new-min new-hour new-date new-month new-year)))

(define-time-method this-hour (time)
    (sec min hour date month year)
  (declare (ignore sec min))
  (encode-universal-time 0 0 hour date month year))

(define-time-method next-hour (time)
    (sec min hour date month year)
  (declare (ignore sec min))
  (let* ((new-hour (normalize-hour (1+ hour)))
	 (new-date (normalize-day (if (< new-hour hour) (1+ date) date) month year))
	 (new-month (normalize-month (if (< new-date date) (1+ month) month)))
	 (new-year (if (< new-month month) (1+ year) year)))
    (encode-universal-time 0 0 new-hour new-date new-month new-year)))

(define-time-method this-day (time)
    (sec min hour date month year)
  (declare (ignore sec min hour))
  (encode-universal-time 0 0 0 date month year))

(define-time-method next-day (time)
    (sec min hour date month year day)
  (declare (ignore sec min hour day))
  (let* ((new-date (normalize-day (1+ date) month year))
	 (new-month (normalize-month (if (< new-date date) (1+ month) month)))
	 (new-year (if (< new-month month) (1+ year) year)))
    (encode-universal-time 0 0 0 new-date new-month new-year)))

(define-time-method this-week (time)
    (sec min hour date month year day)
  (declare (ignore sec min hour))
  (let ((new-date (normalize-day (- date (if (= 6 day) 0 (1+ day))) month year)))
    (encode-universal-time 0 0 0 new-date month year)))

(define-time-method next-week (time)
    (sec min hour date month year day)
  (declare (ignore sec min hour))
  (let* ((new-date (normalize-day (+ date (if (= 6 day) 7 (- 6 day))) month year))
	 (new-month (normalize-month (if (< new-date date) (1+ month) month)))
	 (new-year (if (< new-month month) (1+ year) year)))
    (encode-universal-time 0 0 0 new-date new-month new-year)))

(define-time-method this-month (time)
    (sec min hour date month year)
  (declare (ignore sec min hour date))
  (encode-universal-time 0 0 0 1 month year))

(define-time-method next-month (time)
    (sec min hour date month year)
  (declare (ignore sec min hour date))
  (let* ((new-month (normalize-month (1+ month)))
	 (new-year (if (< new-month month) (1+ year) year)))
    (encode-universal-time 0 0 0 1 new-month new-year)))

(define-time-method this-time (time window) ()
  (ecase window
    (:half-hour (this-half-hour time))
    (:hour (this-hour time))
    (:day (this-day time))
    (:week (this-week time))
    (:month (this-month time))))

(define-time-method next-time (time window) ()
  (ecase window
    (:half-hour (next-half-hour time))
    (:hour (next-hour time))
    (:day (next-day time))
    (:week (next-week time))
    (:month (next-month time))))

(defun time-split (flow-sequence next-time-fun)
  (flet ((%time-split (flow-sequence timestamp)
	   (loop
	      :for flow :in flow-sequence
	      :if (< (timestamp-to-universal (start-time flow)) timestamp)
	      :collect flow :into before
	      :else
	      :collect flow :into after
	      :finally (return (list before after)))))
    (let (split-list)
      (do* ((time
	     (funcall next-time-fun (timestamp-to-universal (start-time (first flow-sequence))))
	     (funcall next-time-fun time))
	    (split (%time-split flow-sequence time)
		   (%time-split (second split) time)))
	   ((and (null (car split)) (null (second split)))	    
	    (nreverse split-list))
	(when (car split)
	  (push (first split) split-list))))))