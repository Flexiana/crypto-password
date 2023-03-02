(ns crypto.password.argon2
  (:import (de.mkammerer.argon2 Argon2 Argon2Factory Argon2Advanced)))

(def argon2 (Argon2Factory/create))

(defn encrypt
  ([raw] (encrypt raw 10 65536 1))
  ([raw iter mem parallel]
   (.hash argon2 iter mem parallel raw)))

(defn check [raw hash]
  (.verify argon2 hash raw))

(defn main [_ password]
  (str password))
