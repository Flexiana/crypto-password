(ns crypto.password.argon2
  (:import (de.mkammerer.argon2 Argon2 Argon2Factory Argon2Advanced)))

(def argon2 (Argon2Factory/create))

(defn encrypt
  "Usage:
    (encrypt raw)
    (encrypt raw iter mem parallel)

  Parameters:
    - raw (str): The raw string to be encrypted.
    - iter (int): The number of iterations to perform. Defaults to 10 if not specified.
    - mem (int): The amount of memory to use in kilobytes. Defaults to 65536 if not specified.
    - parallel (int): The degree of parallelism to use. Defaults to 1 if not specified.

  Returns:
    A byte array containing the encrypted string."
  ([raw] (encrypt raw 10 65536 1))
  ([raw iter mem parallel]
   (.hash argon2 iter mem parallel raw)))

(defn check
  "Usage:
    (check raw hash)

  Parameters:
    - raw (str): The raw string to check against the hash.
    - hash (byte-array): The Argon2 password hash to check against.

  Returns:
    true if the raw string matches the hash, false otherwise."
  [raw hash]
  (.verify argon2 hash raw))

(defn main [_ password]
  (str password))
