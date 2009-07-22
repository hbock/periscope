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
(defparameter *default-offset* -18000)

(defun leap-year-p (year)
  "Returns true if year is a leap year."
  (and (zerop (mod year 4))
       (or (zerop (mod year 400))
           (not (zerop (mod year 100))))))

(defun minimize-part (time part)
  (timestamp-minimize-part time part :offset *default-offset*))

(defun month-days (month year)
  (declare (type (integer 1 12) month))
  (if (and (= month 2) (leap-year-p year))
      29
      (aref +month-days+ month)))

(defun normalize-hour (hour)
  (mod hour 24))

(defun normalize-day (day month year)
  (let ((month-days (month-days month year)))
    (if (> day month-days) (mod day month-days) day)))

(defun normalize-month (month)
  (if (> month 12) (mod month 12) month))

(defmethod next-half-hour ((time timestamp))
  (universal-to-timestamp (next-half-hour (timestamp-to-universal time)))
  ;; (let ((min-hour (minimize-part time :min)))
  ;;   (if (>= (timestamp-minute time) 30)
  ;; 	(timestamp+ min-hour 1 :hour)
  ;; 	(timestamp+ min-hour 30 :minute)))
  )

(defmethod next-half-hour ((time integer))
  (multiple-value-bind (sec min hour date month year day)
      (decode-universal-time time)
    (declare (ignore sec day))
    (let* ((new-min (if (>= min 30) 0 30))
	   (new-hour (normalize-hour (if (< new-min min) (1+ hour) hour)))
	   (new-date (normalize-day (if (< new-hour hour) (1+ date) date) month year))
	   (new-month (normalize-month (if (< new-date date) (1+ month) month)))
	   (new-year (if (< new-month month) (1+ year) year)))
      (encode-universal-time 0 new-min new-hour new-date new-month new-year))))

(defmethod next-hour ((time integer))
  (multiple-value-bind (sec min hour date month year day)
      (decode-universal-time time)
    (declare (ignore sec min day))
    (let* ((new-hour (normalize-hour (1+ hour)))
	   (new-date (normalize-day (if (< new-hour hour) (1+ date) date) month year))
	   (new-month (normalize-month (if (< new-date date) (1+ month) month)))
	   (new-year (if (< new-month month) (1+ year) year)))
      (encode-universal-time 0 0 new-hour new-date new-month new-year))))

(defmethod next-day ((time integer))
  (multiple-value-bind (sec min hour date month year day)
      (decode-universal-time time)
    (declare (ignore sec min hour day))
    (let* ((new-date (normalize-day (1+ date) month year))
	   (new-month (normalize-month (if (< new-date date) (1+ month) month)))
	   (new-year (if (< new-month month) (1+ year) year)))
      (encode-universal-time 0 0 0 new-date new-month new-year))))

(defmethod next-week ((time integer))
  (multiple-value-bind (sec min hour date month year day)
      (decode-universal-time time)
    (declare (ignore sec min hour))
    (let* ((new-date (normalize-day (+ date (if (= 6 day) 7 (- 6 day))) month year))
	   (new-month (normalize-month (if (< new-date date) (1+ month) month)))
	   (new-year (if (< new-month month) (1+ year) year)))
      (encode-universal-time 0 0 0 new-date new-month new-year))))

(defmethod next-month ((time integer))
  (multiple-value-bind (sec min hour date month year day)
      (decode-universal-time time)
    (declare (ignore sec min hour date day))
    (let* ((new-month (normalize-month (1+ month)))
	   (new-year (if (< new-month month) (1+ year) year)))
      (encode-universal-time 0 0 0 1 new-month new-year))))

(defmethod next-hour ((time timestamp))
  ;(timestamp+ (minimize-part time :min) 1 :hour)
  (universal-to-timestamp (next-hour (timestamp-to-universal time))))

(defmethod next-day ((time timestamp))
  ;(timestamp+ (timestamp-minimize-part time :hour) 1 :day)
  (universal-to-timestamp (next-day (timestamp-to-universal time))))

(defmethod next-week ((time timestamp))
  ;; (let ((this-sunday
  ;; 	 (minimize-part
  ;; 	  ;; ADJUST-TIMESTAMP will always return the previous Sunday, but we specifically
  ;; 	  ;; want THIS Sunday - thus, if 'time' is already on a Sunday, we just minimize the
  ;; 	  ;; hours on time as-is.
  ;; 	  (if (zerop (timestamp-day-of-week time))
  ;; 	      time
  ;; 	      (adjust-timestamp time (offset :day-of-week :sunday))) :hour)))
  ;;   (timestamp+ this-sunday 7 :day))
  (universal-to-timestamp (next-week (timestamp-to-universal time))))

(defmethod next-month ((time timestamp))
  ;(timestamp+ (timestamp-minimize-part time :day :offset -18000) 1 :month)
  (universal-to-timestamp (next-month (timestamp-to-universal time))))

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
	    split-list)
	(when (car split)
	  (push (first split) split-list))))))