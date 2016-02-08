;;; Package for load-testing the server using SBCL.
;;; NOTE: Increase the queue size on the server in order to decrease
;;; the number of messages being dropped.
(in-package :cl-user)

(defpackage :bench
  (:use :cl :sb-bsd-sockets)
  (:export :request
           :bogus-request
           :channel-message
           :private-message
           :all))

(in-package :bench)

(defun make-handler-map () (make-hash-table :test 'eq))
(defun set-handler (fd handler map) (setf (gethash fd map) handler))
(defun get-handler (fd map) (gethash fd map))
(defun rem-handler (fd map) (remhash fd map))
(defun empty-handler-map-p (map) (zerop (hash-table-count map)))
(defun cleanup-handler-map (map)
         (maphash #'(lambda (fd handler)
                      (declare (ignore fd))
                      (sb-sys:remove-fd-handler handler))
                  map))

(defvar *num-request-acks*)
(defconstant +request-timeout+ 5)

(defun request (addr port make-sender make-reader num-requests num-workers
                &rest args)
  (let ((addr (make-inet-address addr))
        (read-handlers (make-handler-map))
        (write-handlers (make-handler-map))
        (sockets '()))
    (flet ((speed (start end)
             (format t "requests: ~D, acks: ~D, speed: ~,2F req/s~%"
                     num-requests
                     *num-request-acks*
                     (float (/ (* *num-request-acks*
                                  internal-time-units-per-second)
                               (- end start)))))
           (make-worker (nreq id)
             (let* ((s (make-instance 'inet-socket
                                      :type :stream
                                      :protocol :tcp))
                    (fd (socket-file-descriptor s))
                    (writer (apply make-sender nreq s write-handlers id args))
                    (reader (apply make-reader nreq s read-handlers id args)))
               (socket-connect s addr port)
               (push s sockets)
               (set-handler fd
                            (sb-sys:add-fd-handler fd :output writer)
                            write-handlers)
               (set-handler fd
                            (sb-sys:add-fd-handler fd :input reader)
                            read-handlers))))
      (unwind-protect
           (multiple-value-bind (nreq rem) (floor num-requests num-workers)
             (let ((start (get-internal-real-time))
                   (timeoutp nil))
               (setf *num-request-acks* 0)
               (make-worker (+ nreq rem) 0)
               (loop for id from 1 to (1- num-workers)
                     do (make-worker nreq id))
               (loop until (or (and (empty-handler-map-p read-handlers)
                                    (empty-handler-map-p write-handlers))
                               (setf timeoutp
                                     (not (sb-sys:serve-all-events
                                           +request-timeout+)))))
               (let ((end (get-internal-real-time)))
                 (speed start (if timeoutp (- end +request-timeout+) end)))))
        (cleanup-handler-map read-handlers)
        (cleanup-handler-map write-handlers)
        (dolist (s sockets) (socket-close s))))))

(defvar *bogus-request* (format nil "BOGUS REQUEST~C~%" #\Return))
(defconstant +command-max-size+ 1024)
(defvar *buf* (make-string (* 4 +command-max-size+)))

(defun make-bogus-request-sender (nreq sock write-handlers &rest args)
  (declare (ignore args))
  (let ((offset 0))
    (lambda (fd)
      (let* ((req (if (zerop offset)
                      *bogus-request*
                      (subseq *bogus-request* offset))))
        (incf offset (socket-send sock req (length req) :dontwait t))
        (when (= offset (length *bogus-request*))
          (setf offset 0)
          (when (zerop (decf nreq))
            (sb-sys:remove-fd-handler (get-handler fd write-handlers))
            (rem-handler fd write-handlers)))))))

(defun make-request-receiver (nreq sock read-handlers &rest args)
  (declare (ignore args))
  (let ((pending-return-p nil))
    (lambda (fd)
      (let ((len (nth-value 1 (socket-receive sock *buf* nil :dontwait t)))
            (pos 0))
        (flet ((count-crlf ()
                 (when (char= #\Newline (char *buf* pos))
                   (incf pos)
                   (incf *num-request-acks*)
                   (decf nreq))))
          (when pending-return-p
            (setf pending-return-p nil)
            (count-crlf))
          (loop while (setf pos (position #\Return *buf* :start pos :end len))
                do (when (= (incf pos) len)
                     (setf pending-return-p t)
                     (return))
                   (count-crlf)))
        (assert (>= nreq 0))
        (when (zerop nreq)
          (sb-sys:remove-fd-handler (get-handler fd read-handlers))
          (rem-handler fd read-handlers))))))

(defun bogus-request (addr port &key (num-requests 2000000) (num-workers 6))
  (request addr port #'make-bogus-request-sender #'make-request-receiver
           num-requests num-workers))

(defvar *messages*
  (vector "All that is gold does not glitter,"
          "Not all those who wander are lost;"
          "The old that is strong does not wither,"
          "Deep roots are not reached by the frost."
          "From the ashes a fire shall be woken,"
          "A light from the shadows shall spring;"
          "Renewed shall be blade that was broken,"
          "The crownless again shall be king."))

(defun make-channel-sender (nreq sock write-handlers id &rest args)
  (declare (ignore args))
  (let ((msg (format nil "LOGIN user~D~C~%JOIN #CHANNEL~:*~C~%" id #\Return))
        (offset 0))
    (flet ((send-msg ()
             (let* ((req (if (zerop offset) msg (subseq msg offset))))
               (incf offset (socket-send sock req (length req) :dontwait t))
               (= offset (length msg)))))
      (lambda (fd)
        (when (send-msg)
          (cond ((= (decf nreq) -1)
                 (sb-sys:remove-fd-handler (get-handler fd write-handlers))
                 (rem-handler fd write-handlers))
                (t (setf msg    (format nil "MSG #CHANNEL ~A~C~%"
                                        (svref *messages*
                                               (random (length *messages*)))
                                        #\Return)
                         offset 0))))))))

(defun make-channel-receiver (nreq sock read-handlers &rest args)
  (declare (ignore args))
  (let ((ok (format nil "OK~C~%" #\Return))
        (offset 0)
        (pending-return-p nil))
    (lambda (fd)
      (let ((len (nth-value 1 (socket-receive sock *buf* nil :dontwait t)))
            (pos 0))
        (flet ((count-ok ()
                 (loop
                   (let ((len1 (min (- (length ok) offset) (- len pos))))
                     (unless (string= ok *buf*
                                      :start1 offset :end1 (+ offset len1)
                                      :start2 pos :end2 (+ pos len1))
                       (return))
                     (incf pos len1)
                     (when (< (incf offset len1) (length ok))
                       (return))
                     (setf offset 0)
                     (decf nreq)
                     (incf *num-request-acks*)))))
          (when (and pending-return-p (char= #\Newline (char *buf* 0)))
            (setf pending-return-p nil)
            (incf pos))
          (count-ok)
          (loop while (setf pos (position #\Return *buf* :start pos :end len))
                do (when (= (incf pos) len)
                     (setf pending-return-p t)
                     (return))
                   (when (char= #\Newline (char *buf* pos))
                     (if (= (incf pos) len)
                         (return)
                         (count-ok))))
          (assert (>= nreq -2))
          (when (= nreq -2)
            (sb-sys:remove-fd-handler (get-handler fd read-handlers))
            (rem-handler fd read-handlers)))))))

(defun channel-message (addr port &key (num-messages 500000) (num-workers 2))
  (request addr port #'make-channel-sender #'make-channel-receiver num-messages
           num-workers))

(defun make-pm-sender (nreq sock write-handlers id &rest args)
  (let ((msg (format nil "LOGIN user~D~C~%" id #\Return))
        (offset 0)
        (max-id (first args)))
    (flet ((send-msg ()
             (let* ((req (if (zerop offset) msg (subseq msg offset))))
               (incf offset (socket-send sock req (length req) :dontwait t))
               (= offset (length msg)))))
      (lambda (fd)
        (when (send-msg)
          (cond ((= (decf nreq) -1)
                 (sb-sys:remove-fd-handler (get-handler fd write-handlers))
                 (rem-handler fd write-handlers))
                (t (setf msg    (format nil "MSG user~D ~A~C~%"
                                        (random max-id)
                                        (svref *messages*
                                               (random (length *messages*)))
                                        #\Return)
                         offset 0))))))))

(defun make-pm-receiver (nreq sock read-handlers &rest args)
  (declare (ignore args))
  (let ((ok (format nil "OK~C~%" #\Return))
        (err (format nil "ERROR unknown user~C~%" #\Return))
        (cmd nil)
        (offset 0)
        (pending-return-p nil))
    (lambda (fd)
      (let ((len (nth-value 1 (socket-receive sock *buf* nil :dontwait t)))
            (pos 0))
        (flet ((count-ack ()
                 (loop
                   (when (zerop offset)
                     (setf cmd (if (char= (char *buf* 0) #\E) err ok)))
                   (let ((len1 (min (- (length cmd) offset) (- len pos))))
                     (unless (string= cmd *buf*
                                      :start1 offset :end1 (+ offset len1)
                                      :start2 pos :end2 (+ pos len1))
                       (return))
                     (incf pos len1)
                     (when (< (incf offset len1) (length ok))
                       (return))
                     (setf offset 0)
                     (decf nreq)
                     (incf *num-request-acks*)))))
          (when (and pending-return-p (char= (char *buf* 0) #\Newline))
            (setf pending-return-p nil)
            (incf pos))
          (count-ack)
          (loop while (setf pos (position #\Return *buf* :start pos :end len))
                do (when (= (incf pos) len)
                     (setf pending-return-p t)
                     (return))
                   (when (char= (char *buf* pos) #\Newline)
                     (if (= (incf pos) len)
                         (return)
                         (count-ack))))
          (assert (>= nreq -1))
          (when (= nreq -1)
            (sb-sys:remove-fd-handler (get-handler fd read-handlers))
            (rem-handler fd read-handlers)))))))

(defun private-message (addr port &key (num-messages 1000000) (num-workers 50))
  (request addr port #'make-pm-sender #'make-pm-receiver num-messages
           num-workers num-workers))

;;; WEIGHTS correspond respectively to BOGUS-REQUEST, CHANNEL-MESSAGE
;;; and PRIVATE-MESSAGE.
(defun all (addr port &key (num-requests 1000000)
                           (num-workers 500)
                           (weights #(1 8 1)))
  (let* ((sum (reduce #'+ weights))
         (n (floor (* (/ (svref weights 0) sum)
                      num-workers)))
         (m (floor (* (/ (+ (svref weights 0) (svref weights 1))
                         sum)
                      num-workers))))
    (flet ((make-sender (nreq sock write-handlers id &rest args)
             (apply (cond ((< id n) #'make-bogus-request-sender)
                          ((< id m) #'make-channel-sender)
                          (t #'make-pm-sender))
                    nreq
                    sock
                    write-handlers
                    id
                    args))
           (make-receiver (nreq sock read-handlers id &rest args)
             (apply (cond ((< id n) #'make-request-receiver)
                          ((< id m) #'make-channel-receiver)
                          (t #'make-pm-receiver))
                    nreq
                    sock
                    read-handlers
                    id
                    args)))
      (request addr port #'make-sender #'make-receiver num-requests
               num-workers num-workers))))

