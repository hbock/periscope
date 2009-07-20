;;; Some code borrowed from BABEL-TESTS. 
;;; Copyright (C) 2007-2008, Luis Oliveira  <loliveira@common-lisp.net>
(defpackage :periscope-test
  (:use :common-lisp :periscope :cffi :stefil))

(in-package :periscope-test)

(in-root-suite)
(defsuite* utility-tests)

(defmacro returns (form &rest values)
  "Asserts, through EQUALP, that FORM returns VALUES."
  `(is (equalp (multiple-value-list ,form) (list ,@values))))

(defmacro defstest (name form &body return-values)
  "Similar to RT's DEFTEST."
  `(deftest ,name ()
     (returns ,form ,@(mapcar (lambda (x) `',x) return-values))))

(defun fail (control-string &rest arguments)
  (stefil::record-failure 'stefil::failed-assertion
                          :format-control control-string
                          :format-arguments arguments))

(defun expected (expected &key got)
  (fail "expected ~A, got ~A instead" expected got))

(deftest ip-string-equal (ip desired-result)
  (is (string= (periscope::ip-string ip) desired-result)))

(deftest ip-netmask-string-equal (ip netmask desired-result)
  (is (string= (periscope::ip-string ip netmask) desired-result)))

(deftest ip-strings ()
  (ip-string-equal #x0a000001 "10.0.0.1")
  (ip-string-equal #xC0A80A0A "192.168.10.10")
  (ip-string-equal #xC0A8FFFE "192.168.255.254")
  (ip-netmask-string-equal #xc0a80a00 #xffffff00 "192.168.10.0/24")
  (ip-netmask-string-equal #xc0a80a00 #xfffffff0 "192.168.10.0/28")
  (ip-netmask-string-equal #x0a000000 #xff000000 "10.0.0.0/8")
  (ip-netmask-string-equal 3322406913 4294901760 "198.7.232.1/16"))

(deftest parse-ip-equals (string expected-network expected-netmask &key expected-error junk-allowed)
  (handler-case
      (multiple-value-bind (network netmask)
	  (periscope::parse-ip-string string :junk-allowed junk-allowed)
	(is (eql network expected-network))
	(is (eql netmask expected-netmask)))
    (parse-error (c)
      (is expected-error
	  "Expected network ~a, netmask ~a, got ~a instead."
	  (periscope::ip-string expected-network) (periscope::ip-string expected-netmask) c))
    (:no-error (result)
      (when expected-error
	(expected 'parse-error :got result)))))

(deftest parse-ip-test ()
  (parse-ip-equals "192.168.10.0/24" #xc0a80a00 #xffffff00)
  (parse-ip-equals "192.168.10.0" #xc0a80a00 nil)
  (parse-ip-equals "198.7.232.1" #xc607e801 nil)
  (parse-ip-equals "10.10.50.1000"      nil nil :junk-allowed t)
  (parse-ip-equals "192.168/24"         nil nil :expected-error t)
  (parse-ip-equals "192.168.1000.10/24" nil nil :expected-error t)
  (parse-ip-equals "10.10.50.1000/24"   nil nil :expected-error t)
  (parse-ip-equals "10.10.50.1000/"     nil nil :expected-error t)
  (parse-ip-equals "10.10.50.1024/2057" nil nil :expected-error t)
  (parse-ip-equals "10.10./.1024/2057"  nil nil :expected-error t)
  (parse-ip-equals "1.1.1.888/23"       nil nil :expected-error t)
  (parse-ip-equals "1.1.1.1/34"         nil nil :expected-error t)
  (parse-ip-equals "1.1.1.1/34"         nil nil :junk-allowed t))

(deftest service-name-test ()
  #+linux
  (progn
    (is (string-equal (periscope::service-name 22) "ssh"))
    (is (string-equal (periscope::service-name 21) "ftp"))
    (is (string-equal (periscope::service-name 123 :protocol :tcp) "ntp"))
    (is (string-equal (periscope::service-name 123 :protocol :udp) "ntp"))
    (is (string-equal (periscope::service-name 161) "snmp"))
    (is (= 161 (periscope::service-name 161 :protocol periscope::+ip-proto-igmp+)))
    (is (= 20570 (periscope::service-name 20570)))))

(deftest byte-string-equal (bytes desired-result &key (precision 2))
  (is (string= (periscope::byte-string bytes precision) desired-result)))

(deftest byte-string-test ()
  (byte-string-equal 1024 "1.00 kB")
  (byte-string-equal 1023 "1,023 B")
  (byte-string-equal 10240 "10.00000 kB" :precision 5)
  (byte-string-equal 124125161 "118.37 MB"))

(deftest network-member-test ()
  (is (periscope::network-member-p #x0a000001 #x0a000000 #xffffff00))
  (is (not (periscope::network-member-p #x0a010001 #x0a000000 #xffffff00)))
  (is (not (periscope::network-member-p #x0f000001 #x0a000000 #xffffff00)))
  (is (periscope::network-member-p #xc0a80a0f #xc0a80000 #xffff0000)))

(deftest vlan-name-tests ()
  (let ((periscope::*vlan-names* (make-hash-table)))
    (is (= 100 (periscope::vlan-name 100)))
    (is (= 2000 (periscope::vlan-name 2000)))
    (is (string= (setf (periscope::vlan-name 400) "TEST1") "TEST1"))
    (is (string= (periscope::vlan-name 400) "TEST1"))
    (setf (periscope::vlan-name 400) nil)
    (is (= 400 (periscope::vlan-name 400)))))

(deftest broadcast-test (ip netmask expected-result)
  (is (= expected-result (periscope::broadcast-address ip netmask))))

(deftest broadcast-p-test (ip network netmask expected-result)
  (is (eq expected-result (periscope::broadcast-address-p ip network netmask))))

(deftest broadcast-tests ()
  (broadcast-test #x0a000001 #xffffff00 #x0a0000ff)
  (broadcast-test #x0a123456 #xff000000 #x0affffff)
  (broadcast-test #xc0987654 #xffff0000 #xc098ffff)
  ;; Test 'universal' broadcast address
  (broadcast-p-test #xffffffff #x0a000000 #xff000000 t)
  (broadcast-p-test #xffffffff #x0a0a0000 #xffff0000 t)
  (broadcast-p-test #xffffffff #xc8c9ff00 #xffffff00 t)
  (broadcast-p-test #x0a0000ff #x0a000000 #xffffff00 t)
  ;; Subnet address should be #x0a00ffff
  (broadcast-p-test #x0a0000ff #x0a000000 #xffff0000 nil))

(deftest vlan-string-test (vlan-string expected-result &key expected-error)
  (if expected-error
      (signals parse-error (periscope::vlans-from-string vlan-string))
      (let ((result (periscope::vlans-from-string vlan-string)))
	(is (equalp result expected-result)))))

(deftest vlan-string-tests ()
  (vlan-string-test "100 200 300 400" (list 100 200 300 400))
  (vlan-string-test "100 200 400 300" (list 100 200 300 400))
  (vlan-string-test "100 100, 100 100" (list 100))
  (vlan-string-test "12400 100, 100, 100" nil :expected-error t)
  ;; Bad VLAN ID (> 4095)
  (vlan-string-test "12400, 100, 100, 100" nil :expected-error t)
  ;; Junk
  (vlan-string-test "1200, 12asdasg, 200" nil :expected-error t)
  (vlan-string-test "1200, 12asdasg, 200" nil :expected-error t))

(deftest subnet-string-test (subnet-string expected-result &key expected-error)
  (if expected-error
      (signals parse-error (periscope::subnets-from-string subnet-string))
      (let ((result (periscope::subnets-from-string subnet-string)))
	(is (equalp result expected-result)))))

(deftest subnet-string-tests ()
  (subnet-string-test "192.168.10.0/24" '((#xC0A80A00 . #xFFFFFF00)))
  (subnet-string-test "10.0.0.0/8 192.168.10.0/24"
		      '((#x0A000000 . #xFF000000) (#xC0A80A00 . #xFFFFFF00)))
  (subnet-string-test "192.168.10.0/" nil :expected-error t)
  (subnet-string-test "192.168.0.0/120" nil :expected-error t)
  (subnet-string-test "198.7.0.0/16, 192.168.10.0/24, 10.0.0.0/24"
		      '((#xC6070000 . #xFFFF0000) (#xC0A80A00 . #xFFFFFF00) (#xA000000 . #xFFFFFF00))
		      :expected-error nil)
  (subnet-string-test "198.7.0.0/16, 192.168.10.0/24, 10.0.0.0/240" nil :expected-error t)
  (subnet-string-test "198.7.0.400/16, 192.168.10.0/24, 10.0.0.0/24" nil :expected-error t)
  (subnet-string-test "1aldgajha, asdfa1231, 99ar9gag" nil :expected-error t)
  (subnet-string-test "10.0.0.8/25, asdfa1231, 99ar9gag" nil :expected-error t))
